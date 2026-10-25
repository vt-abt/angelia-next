#include "collector/KrabsConsumer.h"
#include "collector/ProviderEventKinds.h"

#include <krabs.hpp>
#include <evntrace.h>

#include <spdlog/spdlog.h>

#include <fmt/format.h>

#include <atomic>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>

namespace angelia::collector {

namespace {

// --- Callback-side helpers -------------------------------------------
// Every callback runs on a KrabsETW worker thread. Every string we keep
// must be copied out of the raw ETW buffer BEFORE we return, hence the
// materialise-into-pooled-EventRecord pattern.

inline uint64_t timestamp_from(const EVENT_RECORD& r) noexcept {
    return static_cast<uint64_t>(r.EventHeader.TimeStamp.QuadPart);
}

void utf16_to_utf8(const std::wstring& in, std::string& out) {
    if (in.empty()) { out.clear(); return; }
    const int need = WideCharToMultiByte(CP_UTF8, 0, in.data(),
                                         static_cast<int>(in.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (need <= 0) { out.clear(); return; }
    out.resize(static_cast<std::size_t>(need));
    WideCharToMultiByte(CP_UTF8, 0, in.data(), static_cast<int>(in.size()),
                        out.data(), need, nullptr, nullptr);
}

struct AttrsBuilder {
    std::string s;
    bool empty = true;
    AttrsBuilder() { s.reserve(256); s.push_back('{'); }
    template <typename T>
    void kv(const char* key, const T& val) {
        if (!empty) s.push_back(',');
        empty = false;
        fmt::format_to(std::back_inserter(s), "\"{}\":{}", key, val);
    }
    void kv_str(const char* key, std::string_view val) {
        if (!empty) s.push_back(',');
        empty = false;
        fmt::format_to(std::back_inserter(s), "\"{}\":\"", key);
        for (char c : val) {
            switch (c) {
                case '"':  s += "\\\""; break;
                case '\\': s += "\\\\"; break;
                case '\n': s += "\\n";  break;
                case '\r': s += "\\r";  break;
                case '\t': s += "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20)
                        fmt::format_to(std::back_inserter(s), "\\u{:04x}", (unsigned)c);
                    else s.push_back(c);
            }
        }
        s.push_back('"');
    }
    std::string_view finish() { s.push_back('}'); return s; }
};

std::wstring try_wstr(krabs::parser& p, const wchar_t* name) {
    try { return p.parse<std::wstring>(name); } catch (...) { return {}; }
}
uint32_t try_u32(krabs::parser& p, const wchar_t* name) {
    try { return p.parse<uint32_t>(name); } catch (...) { return 0; }
}
uint64_t try_u64(krabs::parser& p, const wchar_t* name) {
    try { return p.parse<uint64_t>(name); } catch (...) { return 0; }
}

// -------- Provider GUIDs (Microsoft manifest-based Kernel-* providers) ----
// These live under the standard user_trace path — no NT Kernel Logger
// singleton, no conflicts with Perf Monitor / Defender / whatever else
// is already logging on the box. Requires an elevated process.
constexpr const wchar_t* kGuidProcess  = L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}";
constexpr const wchar_t* kGuidFileIo   = L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}";
constexpr const wchar_t* kGuidRegistry = L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}";

// Microsoft-Windows-Kernel-Process event IDs.
EventKind process_kind_from_id(uint16_t id) {
    switch (id) {
        case 1:  return EventKind::ProcessStart;
        case 2:  return EventKind::ProcessEnd;
        case 5:  return EventKind::ImageLoad;
        case 6:  return EventKind::ImageUnload;
        default: return EventKind::Unknown;
    }
}

EventKind file_kind_from_id(uint16_t id) {
    return kernel_file_kind_from_id(id);
}

// Microsoft-Windows-Kernel-Registry event IDs. Confirmed against a
// real run: the previous table had 2 mislabeled as DeleteKey when the
// registry provider uses 2 for OpenKey and 3 for DeleteKey.
EventKind registry_kind_from_id(uint16_t id) {
    switch (id) {
        case 1:  return EventKind::RegistryCreateKey;
        case 2:  return EventKind::RegistryOpenKey;
        case 3:  return EventKind::RegistryDeleteKey;
        case 4:  return EventKind::RegistryQueryKey;
        case 5:  return EventKind::RegistrySetValue;
        case 6:  return EventKind::RegistryDeleteValue;
        case 7:  return EventKind::RegistryQueryValueKey;
        case 8:  return EventKind::RegistryEnumerateKey;
        case 9:  return EventKind::RegistryEnumerateValueKey;
        default: return EventKind::Unknown;
    }
}

}  // namespace

struct KrabsConsumer::Impl {
    krabs::user_trace trace;
    std::wstring name;
    // user_trace::enable stores providers by std::ref, so the provider
    // objects MUST outlive the trace. Keep them owned here.
    std::vector<std::unique_ptr<krabs::provider<>>> providers;
    explicit Impl(const std::string& name)
        : trace(std::wstring(name.begin(), name.end())), name(name.begin(), name.end()) {}
};

KrabsConsumer::KrabsConsumer(SqliteWriter& w) : writer_(w) {}
KrabsConsumer::~KrabsConsumer() { stop(); }

void KrabsConsumer::start(const std::string& session_name,
                          const Providers&   providers) {
    impl_ = std::make_unique<Impl>(session_name);

    // Common shell for every callback: acquire pooled record, stamp
    // headers, run the per-provider materialiser, push. Callbacks must
    // never block or throw across ETW boundary.
    auto make_cb = [this](uint8_t provider_id, EventKind (*kind_of_id)(uint16_t),
                          void (*materialise)(const EVENT_RECORD&,
                                              const krabs::trace_context&,
                                              EventRecord&)) {
        return [this, provider_id, kind_of_id, materialise](const EVENT_RECORD& raw,
                                                const krabs::trace_context& ctx) {
            EventRecord* rec = writer_.pool().try_acquire();
            if (!rec) {
                writer_.metrics().pool_drops.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            rec->timestamp_100ns = timestamp_from(raw);
            rec->pid             = raw.EventHeader.ProcessId;
            rec->tid             = raw.EventHeader.ThreadId;
            rec->event_id        = raw.EventHeader.EventDescriptor.Id;
            rec->opcode          = raw.EventHeader.EventDescriptor.Opcode;
            rec->level           = raw.EventHeader.EventDescriptor.Level;
            rec->kind            = kind_of_id(raw.EventHeader.EventDescriptor.Id);
            rec->provider        = provider_id;

            try { materialise(raw, ctx, *rec); }
            catch (...) { /* leave name/attrs empty; still push */ }

            if (!writer_.push(rec)) writer_.pool().release(rec);
        };
    };

    if (providers.process || providers.image_load) {
        auto proc_up = std::make_unique<krabs::provider<>>(krabs::guid(kGuidProcess));
        auto& proc = *proc_up;
        proc.any(0xFFFFFFFFFFFFFFFFULL);   // all keywords
        proc.add_on_event_callback(make_cb(
            1,
            &process_kind_from_id,
            [](const EVENT_RECORD& raw, const krabs::trace_context& ctx, EventRecord& rec) {
                krabs::schema schema(raw, ctx.schema_locator);
                krabs::parser parser(schema);
                std::wstring img  = try_wstr(parser, L"ImageName");
                if (img.empty()) img = try_wstr(parser, L"FileName");
                uint32_t ppid = try_u32(parser, L"ParentProcessID");
                uint32_t spid = try_u32(parser, L"ProcessID");
                std::string s;    utf16_to_utf8(img, s);
                rec.set_name(s);
                AttrsBuilder a;
                if (ppid) a.kv("parent_pid", ppid);
                if (spid) a.kv("subject_pid", spid);
                if (auto base = try_u64(parser, L"ImageBase"); base) a.kv("image_base", base);
                if (auto sz   = try_u64(parser, L"ImageSize"); sz)   a.kv("image_size", sz);
                auto v = a.finish();
                rec.set_payload(v.data(), v.size());
            }));
        impl_->trace.enable(proc);
        impl_->providers.push_back(std::move(proc_up));
    }

    if (providers.file_io) {
        auto file_up = std::make_unique<krabs::provider<>>(krabs::guid(kGuidFileIo));
        auto& file = *file_up;
        // Include the CreateNewFile keyword (0x1000) as well as the
        // lower file-operation keywords exposed by the installed manifest.
        file.any(0x0000000000001FFFULL);
        file.add_on_event_callback(make_cb(
            2,
            &file_kind_from_id,
            [](const EVENT_RECORD& raw, const krabs::trace_context& ctx, EventRecord& rec) {
                krabs::schema schema(raw, ctx.schema_locator);
                krabs::parser parser(schema);
                std::wstring path = try_wstr(parser, L"FileName");
                if (path.empty()) path = try_wstr(parser, L"FilePath");
                if (path.empty()) path = try_wstr(parser, L"OpenPath");
                std::string s;    utf16_to_utf8(path, s);
                rec.set_name(s);
                AttrsBuilder a;
                if (auto io = try_u64(parser, L"IOSize"); io) a.kv("io_size", io);
                auto v = a.finish();
                rec.set_payload(v.data(), v.size());
            }));
        impl_->trace.enable(file);
        impl_->providers.push_back(std::move(file_up));
    }

    if (providers.registry) {
        auto reg_up = std::make_unique<krabs::provider<>>(krabs::guid(kGuidRegistry));
        auto& reg = *reg_up;
        reg.any(0xFFFFFFFFFFFFFFFFULL);
        reg.add_on_event_callback(make_cb(
            3,
            &registry_kind_from_id,
            [](const EVENT_RECORD& raw, const krabs::trace_context& ctx, EventRecord& rec) {
                krabs::schema schema(raw, ctx.schema_locator);
                krabs::parser parser(schema);
                std::wstring name = try_wstr(parser, L"KeyName");
                if (name.empty()) name = try_wstr(parser, L"RelativeName");
                if (name.empty()) name = try_wstr(parser, L"ValueName");
                std::string s;    utf16_to_utf8(name, s);
                rec.set_name(s);
                AttrsBuilder a;
                if (auto st = try_u32(parser, L"Status"); st) a.kv("status", st);
                auto v = a.finish();
                rec.set_payload(v.data(), v.size());
            }));
        impl_->trace.enable(reg);
        impl_->providers.push_back(std::move(reg_up));
    }

    spdlog::info("user_trace enabling: process={} image={} file={} registry={}",
                 providers.process, providers.image_load,
                 providers.file_io, providers.registry);

    running_.store(true, std::memory_order_release);
    thread_ = std::thread([this] {
        try {
            impl_->trace.start();   // blocking until stop
        } catch (const std::exception& e) {
            spdlog::error("user_trace crashed: {}", e.what());
        }
        running_.store(false, std::memory_order_release);
    });
}

void KrabsConsumer::stop() {
    if (impl_ && running_.load(std::memory_order_acquire)) {
        try { impl_->trace.stop(); } catch (...) {}
    }
    if (thread_.joinable()) thread_.join();
    impl_.reset();
}

KrabsConsumer::LossStats KrabsConsumer::query_loss_stats() const {
    LossStats out;
    if (!impl_) return out;
    struct Query {
        EVENT_TRACE_PROPERTIES props{};
        wchar_t name[256]{};
    } query;
    query.props.Wnode.BufferSize = sizeof(query);
    query.props.LoggerNameOffset = offsetof(Query, name);
    const ULONG rc = QueryTraceW(0, impl_->name.c_str(), &query.props);
    if (rc == ERROR_SUCCESS) {
        out.available = true;
        out.events_lost = query.props.EventsLost;
        out.log_buffers_lost = query.props.LogBuffersLost;
        out.realtime_buffers_lost = query.props.RealTimeBuffersLost;
    }
    return out;
}

}  // namespace angelia::collector
