#include "riskscore/StaticScorer.h"

#include "riskscore/Entropy.h"
#include "riskscore/ImportScanner.h"
#include "riskscore/PeImage.h"

#include <windows.h>

#include <fmt/format.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>

namespace angelia::riskscore {

namespace {

// Canonicalise imports into "dll!function" strings, all lowercase.
std::string flatten(const ImportEntry& e) {
    std::string s = e.dll;
    s.push_back('!');
    s.append(e.function);
    return s;
}

// Injection triad in three shapes. Each rule needs ALL its callouts
// present on the same import list to fire — that's what gives it more
// signal than a single-API keyword match.
struct RuleAllOf {
    const char*                  name;
    const char*                  evidence;
    double                       weight;
    std::vector<std::string>     any_of_per_slot;  // slot i satisfied if any listed API is present
};

const std::vector<RuleAllOf>& injection_rules() {
    static const std::vector<RuleAllOf> R = {
        {
            "injection-classic",
            "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — textbook process injection",
            0.55,
            {
                "kernel32.dll!virtualallocex,kernel32.dll!ntallocatevirtualmemory,ntdll.dll!ntallocatevirtualmemory",
                "kernel32.dll!writeprocessmemory,ntdll.dll!ntwritevirtualmemory",
                "kernel32.dll!createremotethread,ntdll.dll!ntcreatethreadex,kernel32.dll!queueuserapc,ntdll.dll!ntqueueapcthread"
            }
        },
        {
            "injection-hollowing",
            "CreateProcess(SUSPENDED) + NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext — process hollowing shape",
            0.65,
            {
                "kernel32.dll!createprocessa,kernel32.dll!createprocessw",
                "ntdll.dll!ntunmapviewofsection",
                "kernel32.dll!writeprocessmemory,ntdll.dll!ntwritevirtualmemory",
                "kernel32.dll!setthreadcontext,kernel32.dll!resumethread"
            }
        },
        {
            "injection-mapview",
            "NtCreateSection + NtMapViewOfSection + shared-mem cross-process handoff",
            0.35,
            {
                "ntdll.dll!ntcreatesection",
                "ntdll.dll!ntmapviewofsection",
                "ntdll.dll!ntopenprocess,kernel32.dll!openprocess"
            }
        },
    };
    return R;
}

const std::vector<RuleAllOf>& ransomware_rules() {
    static const std::vector<RuleAllOf> R = {
        {
            "ransom-crypt-enum-persist",
            "crypto init + directory enumeration + registry persistence — ransomware shape",
            0.55,
            {
                "advapi32.dll!cryptacquirecontexta,advapi32.dll!cryptacquirecontextw,bcrypt.dll!bcryptopenalgorithmprovider",
                "kernel32.dll!findfirstfilea,kernel32.dll!findfirstfilew,kernel32.dll!findfirstfileexw",
                "advapi32.dll!regsetvaluea,advapi32.dll!regsetvaluew,advapi32.dll!regsetvalueexa,advapi32.dll!regsetvalueexw"
            }
        },
        {
            "ransom-shadow-delete",
            "IWbemLocator/vssapi calls — shadow-copy deletion",
            0.7,
            {
                "wbemuuid.dll!clsid_wbemlocator,vssapi.dll!createvsswriter,vssapi.dll!vssusagetype"
            }
        },
    };
    return R;
}

bool slot_satisfied(const std::string& alternatives_csv,
                    const std::unordered_set<std::string>& present) {
    std::size_t start = 0;
    while (start < alternatives_csv.size()) {
        auto end = alternatives_csv.find(',', start);
        if (end == std::string::npos) end = alternatives_csv.size();
        std::string cand = alternatives_csv.substr(start, end - start);
        if (present.count(cand)) return true;
        start = end + 1;
    }
    return false;
}

void run_ruleset(const std::vector<RuleAllOf>& ruleset,
                 const std::unordered_set<std::string>& imports_set,
                 std::vector<Feature>& out) {
    for (const auto& r : ruleset) {
        std::vector<std::string> matched;
        matched.reserve(r.any_of_per_slot.size());
        bool all_ok = true;
        for (const auto& slot : r.any_of_per_slot) {
            if (!slot_satisfied(slot, imports_set)) { all_ok = false; break; }
        }
        if (!all_ok) continue;
        out.push_back({r.name, r.evidence, r.weight});
    }
}

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

}  // namespace

StaticFinding score_pe(const std::filesystem::path& path) {
    StaticFinding f;
    f.path = path;

    PeImage pe;
    if (!pe.open(path)) {
        f.error = pe.last_error();
        return f;
    }
    f.ok                  = true;
    f.machine             = pe.machine();
    f.dll_characteristics = pe.dll_characteristics();
    f.is64                = pe.is64();
    f.image_base          = pe.image_base();
    f.entry_point         = pe.address_of_entry_point();

    // Section entropy + W^X.
    for (const auto& s : pe.sections()) {
        SectionStat st{};
        st.name          = s.name;
        st.virtual_size  = s.virtual_size;
        st.raw_size      = s.raw_size;
        st.entropy       = shannon_entropy(pe.raw(s));
        st.executable    = (s.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        st.writable      = (s.characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        st.exec_and_writable = st.executable && st.writable;
        f.sections.push_back(std::move(st));
    }

    for (const auto& s : f.sections) {
        if (s.executable && s.entropy >= 7.0 && s.raw_size >= 0x1000) {
            f.features.push_back({
                "high-entropy-exec-section",
                fmt::format("{} is executable and entropy={:.2f} (>=7.0) — likely packed/encrypted",
                            s.name, s.entropy),
                0.35 + std::min(0.25, (s.entropy - 7.0) * 0.3)});
        }
        if (s.exec_and_writable) {
            f.features.push_back({
                "wx-section",
                fmt::format("{} is both writable and executable", s.name),
                0.30});
        }
    }
    if (pe.dll_characteristics()) {
        if (!(pe.dll_characteristics() & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) {
            f.features.push_back({"no-aslr",
                "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE not set", 0.10});
        }
        if (!(pe.dll_characteristics() & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)) {
            f.features.push_back({"no-dep",
                "IMAGE_DLLCHARACTERISTICS_NX_COMPAT not set", 0.10});
        }
    }

    // Imports.
    auto imps = scan_imports(pe);
    f.import_count = imps.size();
    std::unordered_set<std::string> present;
    present.reserve(imps.size());
    for (auto& e : imps) {
        auto flat = flatten(e);
        present.insert(flat);
        f.imports_flat.push_back(std::move(flat));
    }
    std::sort(f.imports_flat.begin(), f.imports_flat.end());
    f.imports_flat.erase(std::unique(f.imports_flat.begin(), f.imports_flat.end()),
                         f.imports_flat.end());

    run_ruleset(injection_rules(), present, f.features);
    run_ruleset(ransomware_rules(), present, f.features);

    double s = 0.0;
    for (const auto& feat : f.features) s += feat.weight;
    f.score = clamp01(s);
    return f;
}

namespace {
std::string q(std::string_view v) {
    std::string s; s.reserve(v.size() + 2);
    s.push_back('"');
    for (char c : v) {
        switch (c) {
            case '"':  s += "\\\""; break;
            case '\\': s += "\\\\"; break;
            case '\n': s += "\\n";  break;
            case '\r': s += "\\r";  break;
            case '\t': s += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                    s += fmt::format("\\u{:04x}", (unsigned)c);
                else s.push_back(c);
        }
    }
    s.push_back('"');
    return s;
}
}

std::string to_json(const StaticFinding& f) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"path\": " << q(f.path.string()) << ",\n";
    os << "  \"ok\": " << (f.ok ? "true" : "false") << ",\n";
    if (!f.ok) {
        os << "  \"error\": " << q(f.error) << "\n}\n";
        return os.str();
    }
    os << fmt::format("  \"machine\": {}, \"dll_characteristics\": {}, \"is64\": {},\n",
                      f.machine, f.dll_characteristics, f.is64);
    os << fmt::format("  \"image_base\": \"0x{:x}\", \"entry_point\": \"0x{:x}\",\n",
                      f.image_base, f.entry_point);
    os << fmt::format("  \"import_count\": {}, \"score\": {:.3f},\n",
                      f.import_count, f.score);
    os << "  \"sections\": [";
    for (std::size_t i = 0; i < f.sections.size(); ++i) {
        const auto& s = f.sections[i];
        os << (i ? "," : "") << "\n    {"
           << "\"name\":" << q(s.name)
           << ",\"virtual_size\":" << s.virtual_size
           << ",\"raw_size\":" << s.raw_size
           << ",\"entropy\":" << fmt::format("{:.3f}", s.entropy)
           << ",\"executable\":" << (s.executable ? "true" : "false")
           << ",\"writable\":" << (s.writable ? "true" : "false")
           << ",\"exec_and_writable\":" << (s.exec_and_writable ? "true" : "false")
           << "}";
    }
    os << "\n  ],\n";
    os << "  \"imports_flat\": [";
    for (std::size_t i = 0; i < f.imports_flat.size(); ++i) {
        os << (i ? "," : "") << "\n    " << q(f.imports_flat[i]);
    }
    os << "\n  ],\n";
    os << "  \"features\": [";
    for (std::size_t i = 0; i < f.features.size(); ++i) {
        const auto& x = f.features[i];
        os << (i ? "," : "") << "\n    {"
           << "\"name\":" << q(x.name)
           << ",\"weight\":" << fmt::format("{:.3f}", x.weight)
           << ",\"evidence\":" << q(x.evidence)
           << "}";
    }
    os << "\n  ]\n}\n";
    return os.str();
}

}  // namespace angelia::riskscore
