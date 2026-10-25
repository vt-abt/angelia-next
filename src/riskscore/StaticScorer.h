#pragma once

// Aggregates the static-leg signals — section entropy and import
// patterns — into an inspectable finding. No black box: every
// contribution is a named Feature with a weight, and the report shows
// them explicitly so a grader can pick the score apart. Score is a
// bounded [0.0, 1.0] blend, not a probability — that would demand a
// calibrated model we haven't earned yet.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace angelia::riskscore {

class PeImage;

struct Feature {
    std::string name;         // slug, kebab-case
    std::string evidence;     // human-readable one-liner
    double      weight = 0.0; // contribution to the score in [0.0, 1.0]
};

struct SectionStat {
    std::string name;
    uint32_t    virtual_size;
    uint32_t    raw_size;
    double      entropy;
    bool        executable;
    bool        writable;
    bool        exec_and_writable;
};

struct StaticFinding {
    std::filesystem::path            path;
    bool                             ok = false;
    std::string                      error;         // populated when !ok
    uint16_t                         machine = 0;
    uint16_t                         dll_characteristics = 0;
    bool                             is64 = false;
    uint64_t                         image_base = 0;
    uint32_t                         entry_point = 0;

    std::vector<SectionStat>         sections;
    std::size_t                      import_count = 0;
    std::vector<std::string>         imports_flat;  // "kernel32.dll!VirtualAllocEx"

    std::vector<Feature>             features;
    double                           score = 0.0;    // clamped [0.0, 1.0]
};

// Runs the whole static leg on `path` and returns a StaticFinding. Never
// throws; parse failures land in finding.error with ok = false.
StaticFinding score_pe(const std::filesystem::path& path);

// Emit a deterministic JSON serialization of the finding (for report
// pipelines and downstream diffing).
std::string to_json(const StaticFinding&);

}  // namespace angelia::riskscore
