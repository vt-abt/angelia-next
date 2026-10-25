#pragma once

#include <cstdint>
#include "collector/EventRecord.h"

namespace angelia::collector {

// IDs from Microsoft-Windows-Kernel-File's installed event manifest. These
// numbers are provider IDs, not EventKind's stable SQLite values.
constexpr EventKind kernel_file_kind_from_id(uint16_t id) noexcept {
    switch (id) {
        case 10: return EventKind::FileCreate;   // NameCreate
        case 11: return EventKind::FileDelete;   // NameDelete
        case 12: return EventKind::FileOpen;     // Create/open handle
        case 13: return EventKind::FileCleanup;
        case 14: return EventKind::FileClose;
        case 15: return EventKind::FileRead;
        case 16: return EventKind::FileWrite;
        case 17: return EventKind::FileSetInformation;
        case 18: return EventKind::FileDelete;   // SetDelete
        case 19: return EventKind::FileRename;
        case 20: return EventKind::FileDirectoryEnumeration;
        case 21: return EventKind::FileFlush;
        case 22: return EventKind::FileQueryInformation;
        case 23: return EventKind::FileFsctl;
        case 24: return EventKind::FileOperationEnd;
        case 25: return EventKind::FileDirectoryNotification;
        case 26: return EventKind::FileDelete;   // DeletePath
        case 27: return EventKind::FileRename;   // RenamePath
        case 28: return EventKind::FileSetLink;
        case 29: return EventKind::FileRename;
        case 30: return EventKind::FileCreate;   // CreateNewFile
        case 31: return EventKind::FileSetSecurity;
        case 32: return EventKind::FileQuerySecurity;
        case 33: return EventKind::FileSetEa;
        case 34: return EventKind::FileQueryEa;
        default: return EventKind::Unknown;
    }
}

} // namespace angelia::collector
