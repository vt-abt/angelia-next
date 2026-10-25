#include "crashtriage/CrashArtifact.h"

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include <cctype>

using json = nlohmann::json;

namespace angelia::crashtriage {

const char* to_string(MsecBucket b) noexcept {
    switch (b) {
        case MsecBucket::NotClassified:          return "NotClassified";
        case MsecBucket::Exploitable:            return "Exploitable";
        case MsecBucket::ProbablyExploitable:    return "ProbablyExploitable";
        case MsecBucket::Unknown:                return "Unknown";
        case MsecBucket::ProbablyNotExploitable: return "ProbablyNotExploitable";
        case MsecBucket::NotExploitable:         return "NotExploitable";
    }
    return "NotClassified";
}

namespace {

MsecBucket bucket_from_string(std::string_view s) {
    if (s == "Exploitable")            return MsecBucket::Exploitable;
    if (s == "ProbablyExploitable")    return MsecBucket::ProbablyExploitable;
    if (s == "Unknown")                return MsecBucket::Unknown;
    if (s == "ProbablyNotExploitable") return MsecBucket::ProbablyNotExploitable;
    if (s == "NotExploitable")         return MsecBucket::NotExploitable;
    return MsecBucket::NotClassified;
}

std::string hex(uint32_t v)  { return fmt::format("0x{:08x}", v); }
std::string hex(uint64_t v)  { return fmt::format("0x{:016x}", v); }

uint32_t parse_hex32(const json& j, uint32_t fallback = 0) {
    if (j.is_string()) {
        try { return static_cast<uint32_t>(std::stoull(j.get<std::string>(), nullptr, 0)); }
        catch (...) { return fallback; }
    }
    if (j.is_number_unsigned() || j.is_number_integer()) return j.get<uint32_t>();
    return fallback;
}
uint64_t parse_hex64(const json& j, uint64_t fallback = 0) {
    if (j.is_string()) {
        try { return std::stoull(j.get<std::string>(), nullptr, 0); }
        catch (...) { return fallback; }
    }
    if (j.is_number_unsigned() || j.is_number_integer()) return j.get<uint64_t>();
    return fallback;
}

std::string bytes_to_hex(const uint8_t* p, std::size_t n) {
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) s += fmt::format("{:02x}", p[i]);
    return s;
}
void hex_to_bytes(std::string_view hexstr, uint8_t* out, std::size_t cap, uint32_t& len) {
    len = 0;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hexstr.size() && len < cap; i += 2) {
        int hi = val(hexstr[i]), lo = val(hexstr[i + 1]);
        if (hi < 0 || lo < 0) break;
        out[len++] = static_cast<uint8_t>((hi << 4) | lo);
    }
}

json regs_to_json(const RegisterSnapshot& r) {
    return json{
        {"rip", hex(r.rip)}, {"rsp", hex(r.rsp)}, {"rbp", hex(r.rbp)},
        {"rax", hex(r.rax)}, {"rbx", hex(r.rbx)}, {"rcx", hex(r.rcx)}, {"rdx", hex(r.rdx)},
        {"rsi", hex(r.rsi)}, {"rdi", hex(r.rdi)},
        {"r8",  hex(r.r8)},  {"r9",  hex(r.r9)},  {"r10", hex(r.r10)}, {"r11", hex(r.r11)},
        {"r12", hex(r.r12)}, {"r13", hex(r.r13)}, {"r14", hex(r.r14)}, {"r15", hex(r.r15)},
        {"eflags", hex(static_cast<uint32_t>(r.eflags))},
        {"cs",     static_cast<uint32_t>(r.cs)},
        {"ss",     static_cast<uint32_t>(r.ss)},
    };
}
RegisterSnapshot regs_from_json(const json& j) {
    RegisterSnapshot r{};
    if (!j.is_object()) return r;
    r.rip = parse_hex64(j.value("rip", json{}));
    r.rsp = parse_hex64(j.value("rsp", json{}));
    r.rbp = parse_hex64(j.value("rbp", json{}));
    r.rax = parse_hex64(j.value("rax", json{}));
    r.rbx = parse_hex64(j.value("rbx", json{}));
    r.rcx = parse_hex64(j.value("rcx", json{}));
    r.rdx = parse_hex64(j.value("rdx", json{}));
    r.rsi = parse_hex64(j.value("rsi", json{}));
    r.rdi = parse_hex64(j.value("rdi", json{}));
    r.r8  = parse_hex64(j.value("r8",  json{}));
    r.r9  = parse_hex64(j.value("r9",  json{}));
    r.r10 = parse_hex64(j.value("r10", json{}));
    r.r11 = parse_hex64(j.value("r11", json{}));
    r.r12 = parse_hex64(j.value("r12", json{}));
    r.r13 = parse_hex64(j.value("r13", json{}));
    r.r14 = parse_hex64(j.value("r14", json{}));
    r.r15 = parse_hex64(j.value("r15", json{}));
    r.eflags = parse_hex32(j.value("eflags", json{}));
    if (j.contains("cs")) r.cs = static_cast<uint16_t>(j["cs"].get<uint32_t>());
    if (j.contains("ss")) r.ss = static_cast<uint16_t>(j["ss"].get<uint32_t>());
    return r;
}

json mit_to_json(const MitigationFlags& m) {
    return json{
        {"dep_enabled",                   m.dep_enabled},
        {"aslr_bottom_up",                m.aslr_bottom_up},
        {"aslr_force_relocate",           m.aslr_force_relocate},
        {"aslr_high_entropy",             m.aslr_high_entropy},
        {"cfg_enabled",                   m.cfg_enabled},
        {"cfg_export_suppression",        m.cfg_export_suppression},
        {"cfg_strict_mode",               m.cfg_strict_mode},
        {"cet_user_shadow_stack",         m.cet_user_shadow_stack},
        {"cet_set_context_ip_validation", m.cet_set_context_ip_validation},
        {"cet_block_non_cet_binaries",    m.cet_block_non_cet_binaries},
        {"sehop_enabled",                 m.sehop_enabled},
        {"image_load_no_low_label",       m.image_load_no_low_label},
    };
}
MitigationFlags mit_from_json(const json& j) {
    MitigationFlags m{};
    if (!j.is_object()) return m;
    auto b = [&](const char* k) { return j.contains(k) && j[k].is_boolean() && j[k].get<bool>(); };
    m.dep_enabled                   = b("dep_enabled");
    m.aslr_bottom_up                = b("aslr_bottom_up");
    m.aslr_force_relocate           = b("aslr_force_relocate");
    m.aslr_high_entropy             = b("aslr_high_entropy");
    m.cfg_enabled                   = b("cfg_enabled");
    m.cfg_export_suppression        = b("cfg_export_suppression");
    m.cfg_strict_mode               = b("cfg_strict_mode");
    m.cet_user_shadow_stack         = b("cet_user_shadow_stack");
    m.cet_set_context_ip_validation = b("cet_set_context_ip_validation");
    m.cet_block_non_cet_binaries    = b("cet_block_non_cet_binaries");
    m.sehop_enabled                 = b("sehop_enabled");
    m.image_load_no_low_label       = b("image_load_no_low_label");
    return m;
}

json evidence_to_json(const Evidence& e) {
    return json{{"category", e.category}, {"slug", e.slug}, {"detail", e.detail}};
}
Evidence evidence_from_json(const json& j) {
    Evidence e;
    if (!j.is_object()) return e;
    e.category = j.value("category", "");
    e.slug     = j.value("slug", "");
    e.detail   = j.value("detail", "");
    return e;
}

json analysis_to_json(const AnalysisBlock& a) {
    json j;
    j["zydis_disasm"] = a.zydis_disasm;
    if (a.pattern_offset_rip)       j["pattern_offset_rip"]       = *a.pattern_offset_rip;
    if (a.pattern_offset_stack_top) j["pattern_offset_stack_top"] = *a.pattern_offset_stack_top;
    j["evidence"] = json::array();
    for (const auto& e : a.evidence) j["evidence"].push_back(evidence_to_json(e));
    return j;
}
AnalysisBlock analysis_from_json(const json& j) {
    AnalysisBlock a;
    if (!j.is_object()) return a;
    a.zydis_disasm = j.value("zydis_disasm", "");
    if (j.contains("pattern_offset_rip") && j["pattern_offset_rip"].is_number_unsigned())
        a.pattern_offset_rip = j["pattern_offset_rip"].get<std::size_t>();
    if (j.contains("pattern_offset_stack_top") && j["pattern_offset_stack_top"].is_number_unsigned())
        a.pattern_offset_stack_top = j["pattern_offset_stack_top"].get<std::size_t>();
    if (j.contains("evidence") && j["evidence"].is_array())
        for (const auto& e : j["evidence"]) a.evidence.push_back(evidence_from_json(e));
    return a;
}

json verdict_to_json(const MsecVerdict& v) {
    return json{
        {"bucket",         to_string(v.bucket)},
        {"confidence",     v.confidence},
        {"rationale",      v.rationale},
        {"evidence_slugs", v.evidence_slugs},
    };
}
MsecVerdict verdict_from_json(const json& j) {
    MsecVerdict v;
    if (!j.is_object()) return v;
    v.bucket     = bucket_from_string(j.value("bucket", ""));
    v.confidence = j.value("confidence", 0.0);
    v.rationale  = j.value("rationale", "");
    if (j.contains("evidence_slugs") && j["evidence_slugs"].is_array())
        for (const auto& s : j["evidence_slugs"]) v.evidence_slugs.push_back(s.get<std::string>());
    return v;
}

}  // namespace

std::string to_json(const CrashArtifact& a) {
    json j;
    j["binary_path"]         = a.binary_path;
    j["input_path"]          = a.input_path;
    j["capture_iso8601_utc"] = a.capture_iso8601_utc;
    j["exception_code"]      = hex(a.exception_code);
    j["exception_flags"]     = hex(a.exception_flags);
    j["first_chance"]        = a.first_chance;
    j["fault_address"]       = hex(a.fault_address);
    j["fault_access_type"]   = a.fault_access_type;
    j["registers"]           = regs_to_json(a.registers);
    j["insn_bytes_len"]      = a.insn_bytes_len;
    j["insn_bytes_hex"]      = bytes_to_hex(a.insn_bytes.data(), a.insn_bytes_len);
    j["stack_bytes_len"]     = a.stack_bytes_len;
    j["stack_bytes_hex"]     = bytes_to_hex(a.stack_bytes.data(), a.stack_bytes_len);
    j["mitigations"]         = mit_to_json(a.mitigations);
    j["minidump_path"]       = a.minidump_path;
    if (a.analysis) j["analysis"] = analysis_to_json(*a.analysis);
    if (a.verdict)  j["verdict"]  = verdict_to_json(*a.verdict);
    return j.dump(2);
}

bool from_json_str(std::string_view s, CrashArtifact& out, std::string& err) {
    try {
        auto j = json::parse(s);
        out.binary_path         = j.value("binary_path", "");
        out.input_path          = j.value("input_path", "");
        out.capture_iso8601_utc = j.value("capture_iso8601_utc", "");
        out.exception_code      = parse_hex32(j.value("exception_code", json{}));
        out.exception_flags     = parse_hex32(j.value("exception_flags", json{}));
        out.first_chance        = j.value("first_chance", true);
        out.fault_address       = parse_hex64(j.value("fault_address", json{}));
        out.fault_access_type   = j.value("fault_access_type", uint32_t{0});
        out.registers           = regs_from_json(j.value("registers", json::object()));
        if (j.contains("insn_bytes_hex"))
            hex_to_bytes(j["insn_bytes_hex"].get<std::string>(),
                         out.insn_bytes.data(), out.insn_bytes.size(), out.insn_bytes_len);
        if (j.contains("stack_bytes_hex"))
            hex_to_bytes(j["stack_bytes_hex"].get<std::string>(),
                         out.stack_bytes.data(), out.stack_bytes.size(), out.stack_bytes_len);
        out.mitigations   = mit_from_json(j.value("mitigations", json::object()));
        out.minidump_path = j.value("minidump_path", "");
        if (j.contains("analysis")) out.analysis = analysis_from_json(j["analysis"]);
        if (j.contains("verdict"))  out.verdict  = verdict_from_json(j["verdict"]);
        return true;
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
}

}  // namespace angelia::crashtriage
