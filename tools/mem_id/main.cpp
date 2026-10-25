// P0.2 CLI. Reads the first eight bytes of a file and reports whether it
// looks like a Windows header-bearing crash dump. Exit codes:
//
//   0  — header-bearing (PAGEDU64 or PAGEDUMP)
//   1  — I/O error
//   2  — truncated
//   3  — unknown format (not header-bearing)

#include <cstdio>
#include <cstdlib>
#include <filesystem>

#include "memforensics/DumpIdentify.h"

using namespace angelia::memforensics;

int angelia_cli_run_mem_id(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: mem_id <file>\n");
        return 1;
    }
    std::filesystem::path path = argv[1];
    const DumpInfo info = identify(path);

    std::printf("path      : %s\n", path.string().c_str());
    std::printf("size      : %llu bytes\n", (unsigned long long)info.file_size);
    std::printf("magic     : %02x %02x %02x %02x %02x %02x %02x %02x\n",
        info.magic[0], info.magic[1], info.magic[2], info.magic[3],
        info.magic[4], info.magic[5], info.magic[6], info.magic[7]);
    std::printf("kind      : %s\n", to_string(info.kind));

    if (info.is_header_bearing()) {
        if (info.kind == DumpKind::HeaderBearing64)
            std::printf("verdict   : PAGEDU64 header recognized; run mem-analyze to validate structure\n");
        else
            std::printf("verdict   : PAGEDUMP header recognized; x86 is not supported by mem-analyze\n");
        return 0;
    }

    std::printf("verdict   : REJECT\n");
    std::printf("reason    : %s\n", info.rejection_reason.c_str());
    switch (info.kind) {
        case DumpKind::Truncated: return 2;
        case DumpKind::Unknown:   return 3;
        default:                  return 1;
    }
}
