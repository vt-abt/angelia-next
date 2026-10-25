#pragma once

// Normalised crash artifact — everything the offline analyzer needs, in a
// form that outlives the crashed process. Companion minidump is written
// alongside as a sibling file.
//
// Pipeline shape (each stage rewrites the same JSON with more fields):
//   p04_capture   -> writes capture-time fields (exception + registers +
//                    insn/stack bytes + mitigations)
//   p05_analyze   -> adds `analysis` block (Zydis decode, pattern hits,
//                    per-signal evidence entries)
//   p06_classify  -> adds `verdict` block (MSEC bucket + confidence +
//                    which evidence entries fed the verdict)
//   p07_writeup   -> reads the fully-classified artifact and emits a
//                    human-readable explanation; never rewrites JSON.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace angelia::crashtriage {

// Mirror of GetProcessMitigationPolicy responses. We surface the specific
// bits Stage 4 attributes verdicts against; everything else is dropped
// rather than kept as an opaque blob.
struct MitigationFlags {
    bool dep_enabled                   = false;
    bool aslr_bottom_up                = false;
    bool aslr_force_relocate           = false;
    bool aslr_high_entropy             = false;
    bool cfg_enabled                   = false;
    bool cfg_export_suppression        = false;
    bool cfg_strict_mode               = false;
    bool cet_user_shadow_stack         = false;
    bool cet_set_context_ip_validation = false;
    bool cet_block_non_cet_binaries    = false;
    bool sehop_enabled                 = false;
    bool image_load_no_low_label       = false;
};

struct RegisterSnapshot {
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t rbp = 0;
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0;
    uint64_t r8  = 0, r9  = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint32_t eflags = 0;
    uint16_t cs = 0, ss = 0;
};

// One piece of evidence extracted by the analyzer. Kept as structured
// records rather than free-form text so the classifier can consume them
// deterministically and the writeup layer can quote them faithfully.
struct Evidence {
    std::string category;   // "insn" | "pattern" | "mitigation" | "exception" | "context"
    std::string slug;       // stable identifier, e.g. "top-of-stack-in-pattern"
    std::string detail;     // one-line human-readable
};

enum class MsecBucket : uint8_t {
    NotClassified = 0,
    Exploitable,
    ProbablyExploitable,
    Unknown,
    ProbablyNotExploitable,
    NotExploitable,
};

const char* to_string(MsecBucket) noexcept;

struct MsecVerdict {
    MsecBucket               bucket     = MsecBucket::NotClassified;
    double                   confidence = 0.0;     // [0.0, 1.0]
    std::string              rationale;            // one-line summary
    std::vector<std::string> evidence_slugs;       // Evidence.slug's that drove this verdict
};

struct AnalysisBlock {
    std::string                 zydis_disasm;              // decoded faulting instruction
    std::optional<std::size_t>  pattern_offset_rip;
    std::optional<std::size_t>  pattern_offset_stack_top;
    std::vector<Evidence>       evidence;
};

struct CrashArtifact {
    // Provenance
    std::string binary_path;
    std::string input_path;
    std::string capture_iso8601_utc;

    // Exception
    uint32_t exception_code    = 0;
    uint32_t exception_flags   = 0;
    uint64_t fault_address     = 0;
    uint32_t fault_access_type = 0;
    bool     first_chance      = true;

    // Machine state at crash
    RegisterSnapshot registers;
    std::array<uint8_t, 32>  insn_bytes{};
    uint32_t                 insn_bytes_len  = 0;
    std::array<uint8_t, 256> stack_bytes{};
    uint32_t                 stack_bytes_len = 0;

    MitigationFlags mitigations;
    std::string     minidump_path;

    // Pipeline stages
    std::optional<AnalysisBlock> analysis;
    std::optional<MsecVerdict>   verdict;
};

// nlohmann-json round trip. from_json tolerates missing pipeline-stage
// blocks so p05 can read a bare capture and p06 can read an analyzed
// one. Unknown top-level keys are ignored.
std::string to_json(const CrashArtifact& a);
bool        from_json_str(std::string_view s, CrashArtifact& out, std::string& err);

}  // namespace angelia::crashtriage
