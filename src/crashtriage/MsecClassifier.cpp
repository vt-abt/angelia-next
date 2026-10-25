#include "crashtriage/MsecClassifier.h"

#include <fmt/format.h>

#include <algorithm>
#include <set>
#include <string>

namespace angelia::crashtriage {

namespace {

// Constant slugs the analyzer emits — kept in a single place so classifier
// and writeup speak the same vocabulary. If p05 adds a new slug, add it
// here and (optionally) key a rule off it.
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

bool has(const std::vector<Evidence>& ev, std::string_view s) {
    return std::any_of(ev.begin(), ev.end(),
        [&](const Evidence& e) { return e.slug == s; });
}
void take(std::vector<std::string>& out, std::string_view s) {
    out.emplace_back(s);
}

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

}  // namespace

MsecVerdict classify(CrashArtifact& a) {
    MsecVerdict v;
    if (!a.analysis) {
        v.bucket    = MsecBucket::NotClassified;
        v.rationale = "no analysis block on artifact (run p05_analyze first)";
        a.verdict   = v;
        return v;
    }
    const auto& ev = a.analysis->evidence;

    // ---- Rule 1: /GS or __fastfail intercepted the crash -------------
    // Exception 0xC0000409 is the fast-fail path. The overflow happened,
    // but the mitigation stopped it before RIP was attacker-controlled.
    // Report as NotExploitable but keep the observed-overflow slugs on
    // the verdict so the writeup can say what was actually seen.
    if (a.exception_code == 0xC0000409u || has(ev, slug::fastfail_int29)) {
        v.bucket    = MsecBucket::NotExploitable;
        v.rationale = "STATUS_STACK_BUFFER_OVERRUN — /GS or __fastfail intercepted "
                      "the overflow before saved-RIP could be dereferenced";
        take(v.evidence_slugs, slug::exception_stack_buf_overrun);
        if (has(ev, slug::fastfail_int29))          take(v.evidence_slugs, slug::fastfail_int29);
        if (has(ev, slug::stack_body_in_pattern))   take(v.evidence_slugs, slug::stack_body_in_pattern);
        if (a.mitigations.cfg_enabled)              take(v.evidence_slugs, slug::mitig_cfg_on);
        v.confidence = 0.9;
        a.verdict = v;
        return v;
    }

    // ---- Rule 2: attacker-controlled RIP via return-address overwrite -
    // Fault is an AV, and the top-of-stack qword (or RIP low-32) matches
    // the cyclic pattern. Textbook exploitable.
    if (a.exception_code == 0xC0000005u &&
        (has(ev, slug::stack_top_in_pattern) || has(ev, slug::rip_in_pattern))) {
        v.bucket    = MsecBucket::Exploitable;
        v.rationale = "AV with attacker-controlled return-address value "
                      "(cyclic-pattern hit on saved-RIP slot)";
        take(v.evidence_slugs, slug::exception_av);
        if (has(ev, slug::stack_top_in_pattern)) take(v.evidence_slugs, slug::stack_top_in_pattern);
        if (has(ev, slug::rip_in_pattern))       take(v.evidence_slugs, slug::rip_in_pattern);
        if (has(ev, slug::fault_addr_attacker))  take(v.evidence_slugs, slug::fault_addr_attacker);
        // Confidence higher when multiple pattern signals stack: 0.85 base + 0.05 per extra.
        v.confidence = 0.85;
        if (has(ev, slug::stack_top_in_pattern) && has(ev, slug::rip_in_pattern))
            v.confidence += 0.05;
        if (has(ev, slug::fault_addr_attacker)) v.confidence += 0.05;
        v.confidence = clamp01(v.confidence);
        a.verdict = v;
        return v;
    }

    // ---- Rule 3: heap corruption (STATUS_HEAP_CORRUPTION 0xC0000374) -
    if (a.exception_code == 0xC0000374u || has(ev, slug::exception_heap_corruption)) {
        v.bucket    = MsecBucket::ProbablyExploitable;
        v.rationale = "STATUS_HEAP_CORRUPTION — heap metadata corruption is a "
                      "well-known primitive for arbitrary-write escalation";
        take(v.evidence_slugs, slug::exception_heap_corruption);
        v.confidence = 0.65;
        a.verdict = v;
        return v;
    }

    // ---- Rule 4: AV near NULL — usually a benign dereference, not
    // exploitable in most conditions.
    if (a.exception_code == 0xC0000005u && has(ev, slug::fault_at_null)) {
        v.bucket    = MsecBucket::ProbablyNotExploitable;
        v.rationale = "AV on a fault address near NULL — likely a null-pointer "
                      "dereference rather than attacker-controlled memory";
        take(v.evidence_slugs, slug::exception_av);
        take(v.evidence_slugs, slug::fault_at_null);
        v.confidence = 0.65;
        a.verdict = v;
        return v;
    }

    // ---- Rule 5: illegal / privileged instruction — often indicative of
    // control-flow having landed on data. Probably-exploitable.
    if (a.exception_code == 0xC000001Du ||   // illegal instruction
        a.exception_code == 0xC0000096u ||   // privileged instruction
        has(ev, slug::exception_illegal_insn) ||
        has(ev, slug::exception_priv_insn)) {
        v.bucket    = MsecBucket::ProbablyExploitable;
        v.rationale = "illegal/privileged instruction — execution likely landed on "
                      "unintended bytes";
        v.confidence = 0.55;
        a.verdict = v;
        return v;
    }

    // ---- Fallback: unknown ------------------------------------------
    v.bucket    = MsecBucket::Unknown;
    v.rationale = fmt::format(
        "no confident classifier rule fired for exception 0x{:08x}", a.exception_code);
    v.confidence = 0.25;
    a.verdict = v;
    return v;
}

}  // namespace angelia::crashtriage
