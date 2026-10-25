#pragma once

// A snapshot of the ZwQuerySystemInformation(SystemProcessInformation)
// output, captured at acquisition time so the offline analyzer can
// cross-reference against it. Stored as a JSON file:
//   {
//     "captured_iso8601_utc": "...",
//     "processes": [ {"pid": 1234, "image": "foo.exe"}, ... ]
//   }

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace angelia::memforensics {

struct LiveProcess {
    uint32_t    pid;
    std::string image;
    uint64_t    create_time_100ns = 0;
};

struct LiveSnapshot {
    std::string              captured_iso8601_utc;
    std::vector<LiveProcess> processes;
};

// Capture the running system's live process list into `out`. Returns
// false on failure (and populates `err`); the ZwQuerySystemInformation
// call itself requires no privileges to enumerate PIDs/names.
bool capture_live(LiveSnapshot& out, std::string& err);

bool save_snapshot(const LiveSnapshot& s, const std::filesystem::path& p, std::string& err);
bool load_snapshot(const std::filesystem::path& p, LiveSnapshot& out, std::string& err);

}  // namespace angelia::memforensics
