#pragma once

// P0.2 — physical-memory dump format identification.
//
// The Windows crash-dump family carries a DUMP_HEADER at file offset 0
// whose first eight bytes are ASCII: "PAGEDUMP" for 32-bit, "PAGEDU64"
// for 64-bit. When those bytes are present we know exactly where
// DirectoryTableBase and PsActiveProcessHead live and Stage 2's page-
// table walker can proceed on that footing. Anything else — raw physical
// memory dumps (WinPmem raw / DumpIt raw), truncated files, PDBs handed
// in by mistake — is rejected up front rather than silently mis-parsed.

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>

namespace angelia::memforensics {

enum class DumpKind : uint8_t {
    Unknown = 0,
    Truncated,          // file smaller than the 8-byte magic
    HeaderBearing64,    // PAGEDU64
    HeaderBearing32,    // PAGEDUMP
};

// Offsets within DUMP_HEADER64 that Stage 2 will read. Kept here so the
// identifier and the walker agree on one source of truth; declared as
// constants (not a struct) because we deliberately never blindly memcpy
// the whole header — every read goes through a range check first.
namespace dump64 {
    inline constexpr std::size_t kOffSignature           = 0x00;   // "PAGE"
    inline constexpr std::size_t kOffValidDump           = 0x04;   // "DU64"
    inline constexpr std::size_t kOffDirectoryTableBase  = 0x10;
    inline constexpr std::size_t kOffPfnDatabase         = 0x18;
    inline constexpr std::size_t kOffPsLoadedModuleList  = 0x20;
    inline constexpr std::size_t kOffPsActiveProcessHead = 0x28;
    inline constexpr std::size_t kOffMachineImageType    = 0x30;
}

struct DumpInfo {
    DumpKind             kind = DumpKind::Unknown;
    std::array<uint8_t,8> magic{};    // first 8 bytes read, raw
    uint64_t             file_size = 0;
    std::string          rejection_reason;   // populated when kind == Unknown/Truncated

    bool is_header_bearing() const noexcept {
        return kind == DumpKind::HeaderBearing64 || kind == DumpKind::HeaderBearing32;
    }
};

// Reads the first eight bytes of `path` and classifies. Never throws;
// I/O failure lands in `rejection_reason` with the path and the OS error.
DumpInfo identify(const std::filesystem::path& path) noexcept;

// Human-readable name.
const char* to_string(DumpKind k) noexcept;

}  // namespace angelia::memforensics
