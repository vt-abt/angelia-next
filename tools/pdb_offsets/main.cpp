// P0.3 CLI. Resolves struct-member offsets from a Windows PDB.
//
// Usage:
//     pdb_offsets --image C:\Windows\System32\ntoskrnl.exe
//                 --sym "srv*C:\symbols*https://msdl.microsoft.com/download/symbols"
//                 [--udt _EPROCESS] [--member ActiveProcessLinks]
//     pdb_offsets --pdb path\to\ntkrnlmp.pdb
//                 [--udt _EPROCESS] [--member ActiveProcessLinks]
//
// Exit codes:
//     0 — resolved (offset printed)
//     1 — PDB load failed (error printed)
//     2 — UDT or member not found in the loaded PDB
//     3 — usage error

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include "memforensics/PdbTypeResolver.h"

using namespace angelia::memforensics;

namespace {

struct Args {
    std::string image;
    std::string sym;
    std::string pdb;
    std::wstring udt    = L"_EPROCESS";
    std::wstring member = L"ActiveProcessLinks";
};

std::wstring widen(std::string_view s) {
    return std::wstring(s.begin(), s.end());
}

}  // namespace

int angelia_cli_run_pdb_offsets(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string_view k = argv[i];
        auto need = [&](std::string_view name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %.*s\n",
                             (int)name.size(), name.data());
                std::exit(3);
            }
            return argv[++i];
        };
        if      (k == "--image")  a.image = need(k);
        else if (k == "--sym")    a.sym   = need(k);
        else if (k == "--pdb")    a.pdb   = need(k);
        else if (k == "--udt")    a.udt   = widen(need(k));
        else if (k == "--member") a.member = widen(need(k));
        else { std::fprintf(stderr, "unknown arg: %.*s\n", (int)k.size(), k.data()); return 3; }
    }
    if (a.image.empty() == a.pdb.empty()) {
        std::fprintf(stderr, "specify exactly one of --image or --pdb\n");
        return 3;
    }

    PdbTypeResolver r;
    PdbLoadResult load = a.image.empty()
        ? r.load_pdb(a.pdb)
        : r.load_for_image(a.image, a.sym);

    if (!load.ok) {
        std::fprintf(stderr, "load failed: %s\n", load.error.c_str());
        return 1;
    }
    std::printf("pdb        : %s\n", load.resolved_pdb.c_str());
    std::printf("guid       : %s\n", load.pdb_guid.c_str());
    std::printf("age        : %u\n", load.pdb_age);

    auto off = r.member_offset(a.udt, a.member);
    if (!off) {
        std::fprintf(stderr, "member not found in loaded PDB\n");
        return 2;
    }

    // The wide UDT/member names round-trip through printf via an
    // explicit narrowing cast — kernel symbols we resolve here are ASCII.
    auto narrow = [](const std::wstring& w) {
        std::string s;
        s.reserve(w.size());
        for (wchar_t c : w) s.push_back(c < 0x80 ? static_cast<char>(c) : '?');
        return s;
    };
    std::printf("%s.%s @ 0x%X (%u)\n",
        narrow(a.udt).c_str(), narrow(a.member).c_str(), *off, *off);
    return 0;
}
