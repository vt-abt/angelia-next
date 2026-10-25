// P0.3 — dbghelp-backed PDB type resolver.
//
// Uses SymLoadModuleExW with a symsrv-syntax search path so DIA's lack
// of HTTP support is not on the critical path here. Type walk follows
// the plan verbatim: SymEnumTypesByName to find a UDT, then
// SymGetTypeInfo with TI_GET_CHILDRENCOUNT / TI_FINDCHILDREN /
// TI_GET_SYMNAME / TI_GET_OFFSET.

#include "memforensics/PdbTypeResolver.h"

#include <windows.h>
// dbghelp.h needs winnt.h symbols already in windows.h; keep this order.
#include <dbghelp.h>

#include <fmt/format.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace angelia::memforensics {

namespace {

// dbghelp holds per-process state keyed by HANDLE, and the docs strongly
// recommend serialising API calls. One global mutex is enough — resolver
// lifetime is short and calls are infrequent.
std::mutex& dbghelp_mutex() {
    static std::mutex m;
    return m;
}

// dbghelp needs a unique "process handle" per session. We use a monotonic
// synthetic pointer rather than GetCurrentProcess() so multiple resolvers
// don't step on one another.
HANDLE next_fake_handle() {
    static std::atomic<uintptr_t> counter{0xC0DE'C0DE'0000'0001ull};
    return reinterpret_cast<HANDLE>(counter.fetch_add(1));
}

std::string wide_to_utf8(const wchar_t* w, std::size_t n = std::size_t(-1)) {
    if (!w) return {};
    const int len = (n == std::size_t(-1))
        ? WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr) - 1
        : static_cast<int>(n);
    if (len <= 0) return {};
    std::string s(static_cast<std::size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, static_cast<int>(len),
                        s.data(), len, nullptr, nullptr);
    return s;
}

std::string guid_to_string(const GUID& g) {
    return fmt::format(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
}

std::string last_error(const char* what) {
    const DWORD e = GetLastError();
    return fmt::format("{} failed (GetLastError=0x{:08x})", what, static_cast<uint32_t>(e));
}

}  // namespace

struct PdbTypeResolver::Impl {
    HANDLE   process   = nullptr;
    DWORD64  base_addr = 0;
    bool     sym_init  = false;

    ~Impl() {
        if (sym_init && process) {
            std::lock_guard<std::mutex> g(dbghelp_mutex());
            if (base_addr) SymUnloadModule64(process, base_addr);
            SymCleanup(process);
        }
    }

    bool ensure_init(const std::wstring& sym_path, std::string& err) {
        std::lock_guard<std::mutex> g(dbghelp_mutex());
        if (sym_init) return true;
        process = next_fake_handle();
        // SYMOPT_DEFERRED_LOADS keeps SymLoadModule cheap; SYMOPT_LOAD_LINES
        // is off (we only walk types). SYMOPT_UNDNAME lets SymEnumTypes
        // return demangled names.
        // No SYMOPT_DEFERRED_LOADS: we want SymLoadModuleExW to actually
        // fetch the PDB now so verify_module_state can catch mismatches
        // instead of reporting SymType=SymDeferred.
        SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME
                                     | SYMOPT_DEBUG /* verbose to OutputDebugString */);
        if (!SymInitializeW(process, sym_path.empty() ? nullptr : sym_path.c_str(),
                            /*fInvadeProcess=*/FALSE)) {
            err = last_error("SymInitializeW");
            return false;
        }
        sym_init = true;
        return true;
    }

    PdbLoadResult verify_module_state(const std::wstring& image_or_pdb) {
        PdbLoadResult r;
        IMAGEHLP_MODULEW64 info{};
        info.SizeOfStruct = sizeof(info);
        std::lock_guard<std::mutex> g(dbghelp_mutex());
        if (!SymGetModuleInfoW64(process, base_addr, &info)) {
            r.error = last_error("SymGetModuleInfoW64");
            return r;
        }
        // SymType == SymNone / SymDeferred / SymPdb / SymDia ... A successful
        // symbol load lands on SymPdb (or SymDia when DIA is used internally).
        // Anything else means we did NOT get real types — that's the
        // "mismatched PDB" case, which we reject here rather than lie later.
        if (info.SymType != SymPdb && info.SymType != SymDia) {
            r.error = fmt::format(
                "PDB not resolved for {} (dbghelp SymType={}, tried {}, "
                "loaded pdb=\"{}\"). Symbol-search or GUID/age mismatch.",
                wide_to_utf8(image_or_pdb.c_str()),
                static_cast<int>(info.SymType),
                wide_to_utf8(info.LoadedImageName),
                wide_to_utf8(info.LoadedPdbName));
            return r;
        }
        r.ok           = true;
        r.pdb_guid     = guid_to_string(info.PdbSig70);
        r.pdb_age      = info.PdbAge;
        r.resolved_pdb = wide_to_utf8(info.LoadedPdbName);
        return r;
    }
};

PdbTypeResolver::PdbTypeResolver()  : impl_(std::make_unique<Impl>()) {}
PdbTypeResolver::~PdbTypeResolver() = default;

bool PdbTypeResolver::is_loaded() const noexcept {
    return impl_ && impl_->base_addr != 0;
}

PdbLoadResult PdbTypeResolver::load_for_image(const std::filesystem::path& image,
                                              const std::string& sym_path) {
    PdbLoadResult r;
    const std::wstring wsym(sym_path.begin(), sym_path.end());
    if (!impl_->ensure_init(wsym, r.error)) return r;

    const std::wstring wimg = image.wstring();
    {
        std::lock_guard<std::mutex> g(dbghelp_mutex());
        // Base address = 0 means dbghelp picks one; size = 0 means read it
        // from the image. This kicks off the symsrv download if needed.
        impl_->base_addr = SymLoadModuleExW(impl_->process, /*hFile=*/nullptr,
                                            wimg.c_str(), /*ModuleName=*/nullptr,
                                            /*BaseOfDll=*/0, /*DllSize=*/0,
                                            /*Data=*/nullptr, /*Flags=*/0);
    }
    if (impl_->base_addr == 0) {
        // ERROR_SUCCESS with base=0 means "already loaded"; treat as error.
        r.error = last_error("SymLoadModuleExW");
        return r;
    }
    return impl_->verify_module_state(wimg);
}

PdbLoadResult PdbTypeResolver::load_pdb(const std::filesystem::path& pdb) {
    PdbLoadResult r;
    // For a bare PDB load, point the search path at the PDB's directory so
    // SymLoadModuleExW can locate it when given a "synthetic" image name
    // of the same basename.
    const std::wstring dir  = pdb.parent_path().wstring();
    const std::wstring name = pdb.filename().wstring();
    if (!impl_->ensure_init(dir, r.error)) return r;
    {
        std::lock_guard<std::mutex> g(dbghelp_mutex());
        // Passing the PDB path directly as ModuleName works with dbghelp's
        // fallback for orphan PDBs. Use a synthetic base address; there is
        // no image, so size = 1 keeps dbghelp happy.
        impl_->base_addr = SymLoadModuleExW(impl_->process, /*hFile=*/nullptr,
                                            pdb.wstring().c_str(),
                                            /*ModuleName=*/nullptr,
                                            /*BaseOfDll=*/0x10000000, /*DllSize=*/0x1000,
                                            /*Data=*/nullptr, /*Flags=*/0);
    }
    if (impl_->base_addr == 0) {
        r.error = last_error("SymLoadModuleExW(pdb-direct)");
        return r;
    }
    return impl_->verify_module_state(pdb.wstring());
}

namespace {

struct FindTypeCtx {
    std::wstring want;
    ULONG        type_index = 0;
    bool         found      = false;
};

BOOL CALLBACK on_type(PSYMBOL_INFO sym, ULONG /*size*/, PVOID user) {
    auto* ctx = static_cast<FindTypeCtx*>(user);
    // sym->Name is UTF-8. Convert Ctx->want to UTF-8 too for comparison.
    // Since we only search kernel struct names (ASCII), a naive narrowing
    // is sufficient here.
    std::string want_ascii;
    want_ascii.reserve(ctx->want.size());
    for (wchar_t c : ctx->want) want_ascii.push_back(static_cast<char>(c));
    if (std::strcmp(sym->Name, want_ascii.c_str()) == 0) {
        ctx->type_index = sym->TypeIndex;
        ctx->found      = true;
        return FALSE;   // stop enumeration
    }
    return TRUE;
}

}  // namespace

std::optional<uint32_t> PdbTypeResolver::member_offset(const std::wstring& udt,
                                                       const std::wstring& member) {
    if (!is_loaded()) return std::nullopt;
    std::lock_guard<std::mutex> g(dbghelp_mutex());

    // 1. Locate the UDT by name.
    FindTypeCtx ctx{udt};
    // SymEnumTypesByName wants ANSI in most builds; we go through the W
    // variant when available. It ships in dbghelp 6.1+.
    std::string udt_ansi;
    for (wchar_t c : udt) udt_ansi.push_back(static_cast<char>(c));
    if (!SymEnumTypesByName(impl_->process, impl_->base_addr,
                            udt_ansi.c_str(), on_type, &ctx) || !ctx.found) {
        return std::nullopt;
    }

    // 2. Fetch child count, then the full child array.
    DWORD child_count = 0;
    if (!SymGetTypeInfo(impl_->process, impl_->base_addr, ctx.type_index,
                        TI_GET_CHILDRENCOUNT, &child_count) || child_count == 0) {
        return std::nullopt;
    }
    const std::size_t bytes = sizeof(TI_FINDCHILDREN_PARAMS) +
                              (child_count > 0 ? (child_count - 1) : 0) * sizeof(ULONG);
    std::vector<uint8_t> buf(bytes, 0);
    auto* params = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(buf.data());
    params->Count = child_count;
    params->Start = 0;
    if (!SymGetTypeInfo(impl_->process, impl_->base_addr, ctx.type_index,
                        TI_FINDCHILDREN, params)) {
        return std::nullopt;
    }

    // 3. Walk children, match by name via TI_GET_SYMNAME, return offset.
    for (DWORD i = 0; i < child_count; ++i) {
        const ULONG child_ti = params->ChildId[i];
        WCHAR* name_w = nullptr;
        if (!SymGetTypeInfo(impl_->process, impl_->base_addr, child_ti,
                            TI_GET_SYMNAME, &name_w) || !name_w) continue;
        const bool match = (std::wcscmp(name_w, member.c_str()) == 0);
        LocalFree(name_w);
        if (!match) continue;

        DWORD offset = 0;
        if (!SymGetTypeInfo(impl_->process, impl_->base_addr, child_ti,
                            TI_GET_OFFSET, &offset)) return std::nullopt;
        return static_cast<uint32_t>(offset);
    }
    return std::nullopt;
}

}  // namespace angelia::memforensics
