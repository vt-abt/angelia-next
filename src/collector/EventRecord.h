#pragma once

// Fully materialised event row. Every string is copied out of the
// ETW-owned buffer in the callback; nothing here points back into memory
// the OS may reuse once the callback returns.
//
// One uniform row for the live collector. Provider-specific fields are
// serialized into the attrs payload while the callback owns the ETW buffer.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace angelia::collector {

enum class EventKind : uint8_t {
    Unknown = 0,
    Synthetic,
    // Kernel-Process   -- id 1 / 2
    ProcessStart,
    ProcessEnd,
    // Kernel-ImageLoad -- id 5 / 6 on Kernel-Process
    ImageLoad,
    ImageUnload,
    // Kernel-FileIO (Microsoft-Windows-Kernel-File). Provider IDs are mapped
    // separately in ProviderEventKinds.h; enum values below remain stable.
    FileCreate,
    FileWrite,
    FileRead,
    FileDelete,
    FileRename,
    // Kernel-Registry (Microsoft-Windows-Kernel-Registry)
    //   1 Create, 3 DeleteKey, 5 SetValue, 6 DeleteValue
    RegistryCreateKey,
    RegistryDeleteKey,
    RegistrySetValue,
    RegistryDeleteValue,
    // ---- Below appended after real-run diagnostic — do NOT reorder the
    //      values above; behavioural-scorer SQL still references them by
    //      numeric literal (kind IN (6, 7), etc.).
    FileOpen,               // 15 — real handle-open (id 14 on File)
    FileClose,              // 16 — id 16 on File
    FileCleanup,            // 17 — id 15 on File
    FileFlush,              // 18 — id 17 on File
    FileOperationEnd,       // 19 — id 24 on File (informational)
    RegistryOpenKey,        // 20 — id 2 on Registry
    RegistryQueryKey,       // 21 — id 4 on Registry
    RegistryQueryValueKey,  // 22 — id 7 on Registry
    RegistryEnumerateKey,   // 23 — id 8 on Registry
    RegistryEnumerateValueKey, // 24 — id 9 on Registry
    FileSetInformation,
    FileDirectoryEnumeration,
    FileQueryInformation,
    FileFsctl,
    FileDirectoryNotification,
    FileSetLink,
    FileSetSecurity,
    FileQuerySecurity,
    FileSetEa,
    FileQueryEa,
};

inline const char* to_string(EventKind k) noexcept {
    switch (k) {
        case EventKind::Unknown:              return "Unknown";
        case EventKind::Synthetic:            return "Synthetic";
        case EventKind::ProcessStart:         return "ProcessStart";
        case EventKind::ProcessEnd:           return "ProcessEnd";
        case EventKind::ImageLoad:            return "ImageLoad";
        case EventKind::ImageUnload:          return "ImageUnload";
        case EventKind::FileCreate:           return "FileCreate";
        case EventKind::FileWrite:            return "FileWrite";
        case EventKind::FileRead:             return "FileRead";
        case EventKind::FileDelete:           return "FileDelete";
        case EventKind::FileRename:           return "FileRename";
        case EventKind::RegistryCreateKey:    return "RegistryCreateKey";
        case EventKind::RegistryDeleteKey:    return "RegistryDeleteKey";
        case EventKind::RegistrySetValue:     return "RegistrySetValue";
        case EventKind::RegistryDeleteValue:  return "RegistryDeleteValue";
        case EventKind::FileOpen:                 return "FileOpen";
        case EventKind::FileClose:                return "FileClose";
        case EventKind::FileCleanup:              return "FileCleanup";
        case EventKind::FileFlush:                return "FileFlush";
        case EventKind::FileOperationEnd:         return "FileOperationEnd";
        case EventKind::RegistryOpenKey:          return "RegistryOpenKey";
        case EventKind::RegistryQueryKey:         return "RegistryQueryKey";
        case EventKind::RegistryQueryValueKey:    return "RegistryQueryValueKey";
        case EventKind::RegistryEnumerateKey:     return "RegistryEnumerateKey";
        case EventKind::RegistryEnumerateValueKey:return "RegistryEnumerateValueKey";
        case EventKind::FileSetInformation: return "FileSetInformation";
        case EventKind::FileDirectoryEnumeration: return "FileDirectoryEnumeration";
        case EventKind::FileQueryInformation: return "FileQueryInformation";
        case EventKind::FileFsctl: return "FileFsctl";
        case EventKind::FileDirectoryNotification: return "FileDirectoryNotification";
        case EventKind::FileSetLink: return "FileSetLink";
        case EventKind::FileSetSecurity: return "FileSetSecurity";
        case EventKind::FileQuerySecurity: return "FileQuerySecurity";
        case EventKind::FileSetEa: return "FileSetEa";
        case EventKind::FileQueryEa: return "FileQueryEa";
    }
    return "Unknown";
}

inline constexpr std::size_t kNameCap    = 512;
inline constexpr std::size_t kPayloadCap = 512;   // reused as attrs_json arena

struct alignas(64) EventRecord {
    uint64_t  timestamp_100ns = 0;   // FILETIME-style, UTC
    uint32_t  pid             = 0;
    uint32_t  tid             = 0;
    uint16_t  event_id        = 0;
    uint8_t   opcode          = 0;
    uint8_t   level           = 0;
    EventKind kind            = EventKind::Unknown;
    uint8_t   provider        = 0;   // 1 process, 2 file, 3 registry
    uint8_t   truncated_name  = 0;
    uint8_t   truncated_payload = 0;
    uint8_t   reserved0       = 0;
    uint16_t  name_len        = 0;
    uint16_t  payload_len     = 0;

    std::array<char,    kNameCap>    name{};      // NUL-padded utf-8
    std::array<uint8_t, kPayloadCap> payload{};   // opaque bytes

    void set_name(std::string_view s) noexcept {
        const std::size_t n = std::min(s.size(), kNameCap);
        std::memcpy(name.data(), s.data(), n);
        if (n < kNameCap) name[n] = '\0';
        name_len       = static_cast<uint16_t>(n);
        truncated_name = static_cast<uint8_t>(s.size() > kNameCap);
    }

    void set_payload(const void* p, std::size_t n) noexcept {
        const std::size_t m = std::min(n, kPayloadCap);
        if (p && m) std::memcpy(payload.data(), p, m);
        payload_len       = static_cast<uint16_t>(m);
        truncated_payload = static_cast<uint8_t>(n > kPayloadCap);
    }

    std::string_view name_view() const noexcept {
        return std::string_view{name.data(), name_len};
    }
};

static_assert(std::is_trivially_destructible_v<EventRecord>,
    "EventRecord must be trivially destructible for ObjectPool");

}  // namespace angelia::collector
