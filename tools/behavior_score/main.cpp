// Stage 3 behavioural-leg CLI.
//
//   behavior_score --db collector.db [--pid N] [--json] [--top K]
//
// Reads a Component-1 timeline, scores every PID (or just --pid N),
// prints them ranked by behavioural score. --json emits the raw
// BehavioralReport for downstream integration.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "riskscore/BehavioralScorer.h"

using namespace angelia::riskscore;

namespace {

void print_pid(const PidFeatures& p) {
    std::printf("--- pid=%u  %s   score=%.3f   events=%llu ---\n",
        p.pid, p.image_hint.empty() ? "?" : p.image_hint.c_str(),
        p.score, (unsigned long long)p.event_count);
    std::printf("    starts=%llu  loads=%llu  reads=%llu  writes=%llu  creates=%llu  regsets=%llu\n",
        (unsigned long long)p.process_starts,
        (unsigned long long)p.image_loads,
        (unsigned long long)p.file_reads,
        (unsigned long long)p.file_writes,
        (unsigned long long)p.file_creates,
        (unsigned long long)p.reg_sets);
    std::printf("    distinct: files=%llu  regkeys=%llu    flags: run-persist=%llu  dll-user-writable=%llu\n",
        (unsigned long long)p.distinct_files_written,
        (unsigned long long)p.distinct_regkeys_touched,
        (unsigned long long)p.reg_run_persistence_hits,
        (unsigned long long)p.dlls_from_user_writable);
    if (p.features.empty()) {
        std::printf("    features: (none)\n");
    } else {
        for (const auto& f : p.features) {
            std::printf("    - %-24s  w=%.2f   %s\n", f.name.c_str(), f.weight, f.evidence.c_str());
        }
    }
}

}  // namespace

int angelia_cli_run_behavior(int argc, char** argv) {
    std::filesystem::path db;
    std::optional<uint32_t> only;
    bool as_json = false;
    std::size_t top = 25;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if      (k == "--db" && i + 1 < argc)  db   = argv[++i];
        else if (k == "--pid" && i + 1 < argc) only = static_cast<uint32_t>(std::atoi(argv[++i]));
        else if (k == "--json")                as_json = true;
        else if (k == "--top" && i + 1 < argc) top  = static_cast<std::size_t>(std::atoi(argv[++i]));
        else if (k == "-h" || k == "--help") {
            std::printf("usage: behavior_score --db <path> [--pid N] [--top K] [--json]\n");
            return 0;
        }
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 2; }
    }
    if (db.empty()) { std::fprintf(stderr, "--db is required\n"); return 2; }

    auto r = score_timeline(db, only);
    if (!r.ok) {
        std::fprintf(stderr, "behavior_score: %s\n", r.error.c_str());
        return 1;
    }
    if (as_json) {
        auto j = to_json(r);
        std::fwrite(j.data(), 1, j.size(), stdout);
        return 0;
    }
    std::printf("=== behavioural report ===\n");
    std::printf("total events   : %llu\n", (unsigned long long)r.total_events);
    std::printf("distinct pids  : %llu\n", (unsigned long long)r.distinct_pids);
    std::printf("printing top %zu by score:\n\n", top);
    for (std::size_t i = 0; i < r.pids.size() && i < top; ++i) {
        print_pid(r.pids[i]);
        std::printf("\n");
    }
    return 0;
}
