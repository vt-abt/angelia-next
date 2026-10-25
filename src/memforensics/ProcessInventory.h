#pragma once

// Cross-references a raw-walk process list (from ActiveProcessWalker,
// which sees whatever is on the ActiveProcessLinks doubly-linked list)
// against a LiveSnapshot. The two captures are taken at different times;
// a difference is a review item, never proof of a hidden process.

#include <cstdint>
#include <string>
#include <vector>

#include "memforensics/ActiveProcessWalker.h"
#include "memforensics/LiveProcessSnapshot.h"

namespace angelia::memforensics {

struct InventoryEntry {
    uint32_t    pid                 = 0;
    std::string image_raw;          // ImageFileName from _EPROCESS (short)
    std::string image_live;         // full path from NtQuery
    uint64_t    eprocess_va         = 0;
    uint32_t    parent_pid          = 0;
    bool        seen_in_raw_walk    = false;
    bool        seen_in_live        = false;
    bool        raw_only            = false;   // dump list, absent from later/earlier snapshot
    bool        snapshot_only       = false;   // snapshot, absent from dump list
};

struct Inventory {
    std::vector<InventoryEntry> entries;
    std::size_t raw_only_count() const noexcept {
        std::size_t n = 0;
        for (const auto& e : entries) if (e.raw_only) ++n;
        return n;
    }
};

Inventory build_inventory(const std::vector<RawProcessRecord>& raw,
                          const LiveSnapshot* live /* may be null */);

std::string to_json(const Inventory&);

}  // namespace angelia::memforensics
