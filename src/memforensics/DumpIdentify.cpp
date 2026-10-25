#include "memforensics/DumpIdentify.h"

#include <fmt/format.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <system_error>

namespace angelia::memforensics {

namespace {

constexpr std::array<uint8_t, 8> kPage64 = {'P','A','G','E','D','U','6','4'};
constexpr std::array<uint8_t, 8> kPage32 = {'P','A','G','E','D','U','M','P'};

}  // namespace

const char* to_string(DumpKind k) noexcept {
    switch (k) {
        case DumpKind::Unknown:          return "unknown";
        case DumpKind::Truncated:        return "truncated";
        case DumpKind::HeaderBearing64:  return "PAGEDU64";
        case DumpKind::HeaderBearing32:  return "PAGEDUMP";
    }
    return "unknown";
}

DumpInfo identify(const std::filesystem::path& path) noexcept {
    DumpInfo info;
    std::error_code ec;
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec) {
        info.rejection_reason = fmt::format(
            "cannot stat {}: {}", path.string(), ec.message());
        return info;
    }
    info.file_size = sz;
    if (sz < info.magic.size()) {
        info.kind = DumpKind::Truncated;
        info.rejection_reason = fmt::format(
            "{} is {} byte(s); need at least {} for a dump-header magic",
            path.string(), sz, info.magic.size());
        return info;
    }

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        info.rejection_reason = fmt::format(
            "cannot open {} for reading", path.string());
        return info;
    }
    f.read(reinterpret_cast<char*>(info.magic.data()),
           static_cast<std::streamsize>(info.magic.size()));
    if (f.gcount() != static_cast<std::streamsize>(info.magic.size())) {
        info.kind = DumpKind::Truncated;
        info.rejection_reason = fmt::format(
            "short read on {}: got {} of {} magic bytes",
            path.string(), f.gcount(), info.magic.size());
        return info;
    }

    if (info.magic == kPage64) {
        info.kind = DumpKind::HeaderBearing64;
        return info;
    }
    if (info.magic == kPage32) {
        info.kind = DumpKind::HeaderBearing32;
        return info;
    }

    // Not a header-bearing dump — refuse rather than guess. The message
    // includes the actual bytes so the caller can tell "raw physical
    // memory" apart from "wrong file entirely" (PDB, ELF, garbage).
    info.kind = DumpKind::Unknown;
    info.rejection_reason = fmt::format(
        "{} does not begin with a Windows crash-dump magic; "
        "first 8 bytes = {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} "
        "(\"{}{}{}{}{}{}{}{}\"). "
        "Header-bearing dumps start with PAGEDU64 (x64) or PAGEDUMP (x86); "
        "raw physical dumps (WinPmem raw / DumpIt raw) are not accepted by "
        "this path — re-acquire with a header-writing tool.",
        path.string(),
        info.magic[0], info.magic[1], info.magic[2], info.magic[3],
        info.magic[4], info.magic[5], info.magic[6], info.magic[7],
        char(info.magic[0] >= 0x20 && info.magic[0] < 0x7f ? info.magic[0] : '.'),
        char(info.magic[1] >= 0x20 && info.magic[1] < 0x7f ? info.magic[1] : '.'),
        char(info.magic[2] >= 0x20 && info.magic[2] < 0x7f ? info.magic[2] : '.'),
        char(info.magic[3] >= 0x20 && info.magic[3] < 0x7f ? info.magic[3] : '.'),
        char(info.magic[4] >= 0x20 && info.magic[4] < 0x7f ? info.magic[4] : '.'),
        char(info.magic[5] >= 0x20 && info.magic[5] < 0x7f ? info.magic[5] : '.'),
        char(info.magic[6] >= 0x20 && info.magic[6] < 0x7f ? info.magic[6] : '.'),
        char(info.magic[7] >= 0x20 && info.magic[7] < 0x7f ? info.magic[7] : '.'));
    return info;
}

}  // namespace angelia::memforensics
