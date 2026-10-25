// p05_analyze — reads a bare crash artifact from p04_capture, Zydis-
// decodes the faulting instruction, correlates the stack window and
// registers against the cyclic pattern, and rewrites the artifact JSON
// with an "analysis" block containing structured Evidence entries.
//
// Evidence slugs match those consumed by MsecClassifier (Stage 4's
// deterministic bucketing). No verdict is emitted here — that's p06's
// job. Same file is read and rewritten in place unless --out is given.

#include <Zydis/Zydis.h>

#include <fmt/format.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include "crashtriage/CrashArtifact.h"
#include "crashtriage/CyclicPattern.h"

namespace ac = angelia::crashtriage;

namespace {

std::string zydis_decode(const uint8_t* buf, std::size_t len, uint64_t rip) {
    if (len == 0) return "<no bytes>";
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, len, &insn, ops)))
        return "<zydis: decode failed>";
    char out[256] = {};
    ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible,
                                    out, sizeof(out), rip, nullptr);
    return std::string(out);
}

// The int 0x29 (cd 29) is the __fastfail path — its presence in the
// faulting-insn window is a hard signal for GS/CFG-triggered fast-fail
// even when the OS also gave us the 0xC0000409 exception code.
bool insn_starts_with_int29(const uint8_t* p, std::size_t n) {
    return n >= 2 && p[0] == 0xCD && p[1] == 0x29;
}

// Same shape as the classifier's slug namespace. Kept in sync manually.
namespace slug {
constexpr const char* faulting_insn                = "faulting-insn";
constexpr const char* rip_in_pattern               = "rip-low32-in-pattern";
constexpr const char* stack_top_in_pattern         = "top-of-stack-in-pattern";
constexpr const char* stack_body_in_pattern        = "stack-body-in-pattern";
constexpr const char* reg_in_pattern               = "register-in-pattern";
constexpr const char* exception_av                 = "exception-av";
constexpr const char* exception_stack_buf_overrun  = "exception-stack-buffer-overrun";
constexpr const char* exception_heap_corruption    = "exception-heap-corruption";
constexpr const char* exception_illegal_insn       = "exception-illegal-instruction";
constexpr const char* exception_priv_insn          = "exception-privileged-instruction";
constexpr const char* fault_at_null                = "fault-address-near-null";
constexpr const char* fault_addr_attacker          = "fault-address-attacker-controlled";
constexpr const char* fastfail_int29               = "fastfail-int29";
constexpr const char* mitig_cfg_on                 = "mitigation-cfg-on";
constexpr const char* mitig_aslr_high_entropy      = "mitigation-aslr-high-entropy";
constexpr const char* mitig_dep_on                 = "mitigation-dep-on";
}  // namespace slug

std::optional<std::size_t> pattern_at(const uint8_t* p, std::size_t n, std::size_t off) {
    if (off + 4 > n) return std::nullopt;
    uint32_t v = static_cast<uint32_t>(p[off]) |
                 (static_cast<uint32_t>(p[off + 1]) <<  8) |
                 (static_cast<uint32_t>(p[off + 2]) << 16) |
                 (static_cast<uint32_t>(p[off + 3]) << 24);
    return ac::find_offset(v);
}

}  // namespace

int angelia_cli_run_analyze(int argc, char** argv) {
    std::filesystem::path in_path;
    std::filesystem::path out_path;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if      (k == "--out" && i + 1 < argc) out_path = argv[++i];
        else if (k[0] != '-')                  in_path  = std::string(k);
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 2; }
    }
    if (in_path.empty()) {
        std::fprintf(stderr, "usage: p05_analyze <artifact.json> [--out <path>]\n");
        return 2;
    }
    if (out_path.empty()) out_path = in_path;

    std::ifstream f(in_path);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", in_path.string().c_str()); return 1; }
    std::stringstream ss; ss << f.rdbuf();
    ac::CrashArtifact a;
    std::string err;
    if (!ac::from_json_str(ss.str(), a, err)) {
        std::fprintf(stderr, "parse: %s\n", err.c_str());
        return 1;
    }

    ac::AnalysisBlock ana;
    ana.zydis_disasm = zydis_decode(a.insn_bytes.data(), a.insn_bytes_len, a.registers.rip);

    // ---- Evidence collection --------------------------------------------
    if (a.insn_bytes_len > 0) {
        ana.evidence.push_back({"insn", slug::faulting_insn,
            fmt::format("faulting instruction: {}", ana.zydis_disasm)});
    }
    if (insn_starts_with_int29(a.insn_bytes.data(), a.insn_bytes_len)) {
        ana.evidence.push_back({"insn", slug::fastfail_int29,
            "faulting insn begins with 'cd 29' (int 0x29) — __fastfail"});
    }

    // Register-in-pattern: RIP low 32 for a control-of-RIP AV.
    if (auto off = ac::find_offset(static_cast<uint32_t>(a.registers.rip & 0xFFFF'FFFFu))) {
        ana.pattern_offset_rip = *off;
        ana.evidence.push_back({"pattern", slug::rip_in_pattern,
            fmt::format("RIP low32 matches cyclic pattern at input offset {}", *off)});
    }
    // Fault-address-in-pattern: attacker chose a target for a WRITE AV.
    if (auto off = ac::find_offset(static_cast<uint32_t>(a.fault_address & 0xFFFF'FFFFu))) {
        ana.evidence.push_back({"pattern", slug::fault_addr_attacker,
            fmt::format("fault_address low32 matches cyclic pattern at input offset {}", *off)});
    }
    // Fault-near-null: unmapped low addresses are the ordinary null-deref shape.
    if (a.exception_code == 0xC0000005u && a.fault_address < 0x10000ull &&
        a.fault_address != 0xFFFF'FFFF'FFFF'FFFFull) {
        ana.evidence.push_back({"context", slug::fault_at_null,
            fmt::format("fault_address = 0x{:x} (< 0x10000)", a.fault_address)});
    }

    // Stack window scan for pattern hits.
    if (a.stack_bytes_len > 0) {
        if (auto off = pattern_at(a.stack_bytes.data(), a.stack_bytes_len, 0)) {
            ana.pattern_offset_stack_top = *off;
            ana.evidence.push_back({"pattern", slug::stack_top_in_pattern,
                fmt::format("top-of-stack qword (candidate saved-RIP) matches "
                            "cyclic pattern at input offset {}", *off)});
        }
        std::size_t reported = 0;
        for (std::size_t i = 4; i + 4 <= a.stack_bytes_len; i += 4) {
            if (auto off = pattern_at(a.stack_bytes.data(), a.stack_bytes_len, i)) {
                ana.evidence.push_back({"pattern", slug::stack_body_in_pattern,
                    fmt::format("stack+{} matches pattern at input offset {}", i, *off)});
                if (++reported >= 3) break;
            }
        }
    }

    // Register scan (rax..rdi + r8..r15).
    struct RegRef { const char* name; uint64_t val; };
    const RegRef regs[] = {
        {"rax", a.registers.rax}, {"rbx", a.registers.rbx}, {"rcx", a.registers.rcx},
        {"rdx", a.registers.rdx}, {"rsi", a.registers.rsi}, {"rdi", a.registers.rdi},
        {"r8",  a.registers.r8},  {"r9",  a.registers.r9},  {"r10", a.registers.r10},
        {"r11", a.registers.r11}, {"r12", a.registers.r12}, {"r13", a.registers.r13},
        {"r14", a.registers.r14}, {"r15", a.registers.r15},
    };
    for (const auto& r : regs) {
        if (auto off = ac::find_offset(static_cast<uint32_t>(r.val & 0xFFFF'FFFFu))) {
            ana.evidence.push_back({"pattern", slug::reg_in_pattern,
                fmt::format("{} low32 matches cyclic pattern at input offset {}", r.name, *off)});
        }
    }

    // Exception-code descriptors.
    switch (a.exception_code) {
        case 0xC0000005u:
            ana.evidence.push_back({"exception", slug::exception_av,
                "STATUS_ACCESS_VIOLATION (0xC0000005)"}); break;
        case 0xC0000409u:
            ana.evidence.push_back({"exception", slug::exception_stack_buf_overrun,
                "STATUS_STACK_BUFFER_OVERRUN (0xC0000409) — /GS or __fastfail"}); break;
        case 0xC0000374u:
            ana.evidence.push_back({"exception", slug::exception_heap_corruption,
                "STATUS_HEAP_CORRUPTION (0xC0000374)"}); break;
        case 0xC000001Du:
            ana.evidence.push_back({"exception", slug::exception_illegal_insn,
                "STATUS_ILLEGAL_INSTRUCTION (0xC000001D)"}); break;
        case 0xC0000096u:
            ana.evidence.push_back({"exception", slug::exception_priv_insn,
                "STATUS_PRIVILEGED_INSTRUCTION (0xC0000096)"}); break;
        default: break;
    }

    // Mitigation snapshot as evidence — the classifier folds these into
    // its rationale so "mitigated" verdicts can name what was on.
    if (a.mitigations.cfg_enabled)
        ana.evidence.push_back({"mitigation", slug::mitig_cfg_on, "CFG enabled"});
    if (a.mitigations.aslr_high_entropy)
        ana.evidence.push_back({"mitigation", slug::mitig_aslr_high_entropy, "high-entropy ASLR"});
    if (a.mitigations.dep_enabled)
        ana.evidence.push_back({"mitigation", slug::mitig_dep_on, "DEP enabled"});

    a.analysis = std::move(ana);

    // Write enriched artifact back.
    std::ofstream out(out_path, std::ios::binary | std::ios::trunc);
    if (!out) { std::fprintf(stderr, "cannot write %s\n", out_path.string().c_str()); return 1; }
    auto js = ac::to_json(a);
    out.write(js.data(), static_cast<std::streamsize>(js.size()));

    // Human-readable one-liner to stdout for at-a-glance use.
    std::printf("analyzed: %s\n", out_path.string().c_str());
    std::printf("  exception     : 0x%08x\n", a.exception_code);
    std::printf("  faulting insn : %s\n", a.analysis->zydis_disasm.c_str());
    std::printf("  evidence      : %zu entries\n", a.analysis->evidence.size());
    for (const auto& e : a.analysis->evidence)
        std::printf("    [%s] %-32s  %s\n", e.category.c_str(), e.slug.c_str(), e.detail.c_str());
    return 0;
}
