// Capture a live NtQuerySystemInformation(SystemProcessInformation)
// snapshot to a JSON file for later cross-reference against a memory
// dump acquired at (roughly) the same time. Requires no elevation.
//
//   sys_snapshot --out snapshot.json

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string_view>

#include "memforensics/LiveProcessSnapshot.h"

using namespace angelia::memforensics;

int angelia_cli_run_sys_snapshot(int argc, char** argv) {
    std::filesystem::path out{"snapshot.json"};
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        if (k == "--out" && i + 1 < argc) out = argv[++i];
        else if (k == "-h" || k == "--help") {
            std::printf("usage: sys_snapshot [--out <path>]\n");
            return 0;
        }
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 2; }
    }
    LiveSnapshot s;
    std::string err;
    if (!capture_live(s, err)) { std::fprintf(stderr, "capture: %s\n", err.c_str()); return 1; }
    if (!save_snapshot(s, out, err)) { std::fprintf(stderr, "save: %s\n", err.c_str()); return 1; }
    std::printf("captured %zu processes to %s\n", s.processes.size(), out.string().c_str());
    return 0;
}
