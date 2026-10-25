// Stage 3 static-leg CLI.
//
// Usage:
//   pe_score [--json] <path> [<path> ...]
//
// Emits a human-readable summary per file by default; --json produces
// the machine-readable StaticFinding schema. Exit code is 0 if every
// file parsed and 1 otherwise — the score itself is not a pass/fail.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "riskscore/StaticScorer.h"

using namespace angelia::riskscore;

namespace {

void print_human(const StaticFinding& f) {
    std::printf("=== %s ===\n", f.path.string().c_str());
    if (!f.ok) { std::printf("  parse error: %s\n\n", f.error.c_str()); return; }
    std::printf("  machine=0x%04x  is64=%s  image_base=0x%llx  entry=0x%x\n",
                f.machine, f.is64 ? "yes" : "no",
                (unsigned long long)f.image_base, f.entry_point);
    std::printf("  imports=%zu  score=%.3f\n", f.import_count, f.score);
    std::printf("  sections:\n");
    for (const auto& s : f.sections) {
        std::printf("    %-9s  vs=0x%08x  raw=0x%08x  H=%.2f  %s%s%s\n",
                    s.name.c_str(), s.virtual_size, s.raw_size, s.entropy,
                    s.executable ? "X" : "-",
                    s.writable   ? "W" : "-",
                    s.exec_and_writable ? "  [W^X!]" : "");
    }
    if (f.features.empty()) {
        std::printf("  features: (none matched)\n");
    } else {
        std::printf("  features (%zu):\n", f.features.size());
        for (const auto& x : f.features) {
            std::printf("    - %-30s  w=%.2f   %s\n",
                        x.name.c_str(), x.weight, x.evidence.c_str());
        }
    }
    std::printf("\n");
}

}  // namespace

int angelia_cli_run_score(int argc, char** argv) {
    bool as_json = false;
    std::vector<std::string> paths;
    for (int i = 1; i < argc; ++i) {
        std::string_view a = argv[i];
        if      (a == "--json") as_json = true;
        else if (a == "-h" || a == "--help") {
            std::printf("usage: pe_score [--json] <path> [<path> ...]\n");
            return 0;
        }
        else paths.emplace_back(a);
    }
    if (paths.empty()) { std::fprintf(stderr, "no files given\n"); return 2; }

    int rc = 0;
    if (as_json) std::printf("[");
    for (std::size_t i = 0; i < paths.size(); ++i) {
        auto f = score_pe(paths[i]);
        if (!f.ok) rc = 1;
        if (as_json) {
            if (i) std::printf(",");
            std::string j = to_json(f);
            std::fwrite(j.data(), 1, j.size(), stdout);
        } else {
            print_human(f);
        }
    }
    if (as_json) std::printf("]\n");
    return rc;
}
