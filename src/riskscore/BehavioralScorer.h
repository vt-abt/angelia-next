#pragma once

// Behavioural risk scoring over a Component-1 timeline SQLite.
//
// Per-PID features extracted from the `events` table + a small set of
// deterministic rules. The plan is explicit: don't reach for a Markov /
// n-gram model until we've measured whether the deterministic features
// separate benign from suspicious. score_timeline() emits the raw
// features alongside every finding so the "should we go ML?" question
// can be answered with numbers, not guesses.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "riskscore/StaticScorer.h"   // reuses Feature struct

namespace angelia::riskscore {

struct BigramCount {
    int32_t  from_kind;    // EventKind enum value
    int32_t  to_kind;
    uint64_t count;
};

struct PidFeatures {
    uint32_t     pid                        = 0;
    std::string  image_hint;                // best-effort name from first ProcessStart / ImageLoad
    uint64_t     first_seen_100ns           = 0;
    uint64_t     last_seen_100ns            = 0;
    uint64_t     event_count                = 0;

    uint64_t     process_starts             = 0;
    uint64_t     image_loads                = 0;
    uint64_t     file_creates               = 0;
    uint64_t     file_writes                = 0;
    uint64_t     file_reads                 = 0;
    uint64_t     file_deletes               = 0;
    uint64_t     reg_sets                   = 0;
    uint64_t     reg_deletes                = 0;

    uint64_t     distinct_files_written     = 0;
    uint64_t     distinct_regkeys_touched   = 0;
    uint64_t     dlls_from_user_writable    = 0;   // ImageLoad from AppData/Temp/Downloads
    uint64_t     reg_run_persistence_hits   = 0;   // writes to Run/RunOnce paths

    std::vector<BigramCount> transitions;          // per-PID kind→kind bigrams

    std::vector<Feature> features;
    double       score                      = 0.0;
};

struct BehavioralReport {
    bool                         ok = false;
    std::string                  error;
    uint64_t                     total_events   = 0;
    uint64_t                     distinct_pids  = 0;
    std::vector<PidFeatures>     pids;           // sorted by score desc
};

BehavioralReport score_timeline(const std::filesystem::path& db,
                                std::optional<uint32_t> only_pid = std::nullopt);

std::string to_json(const BehavioralReport&);

}  // namespace angelia::riskscore
