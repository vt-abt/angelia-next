#pragma once

// Walks _EPROCESS.ActiveProcessLinks starting at PsActiveProcessHead
// through a PageTableWalker. Reads UniqueProcessId + ImageFileName per
// entry using the offsets we resolved from the kernel PDB. Bounded by
// max_iter to avoid infinite loops on corrupted or hostile lists.

#include <cstdint>
#include <string>
#include <vector>

#include "memforensics/KernelStructureCache.h"

namespace angelia::memforensics {

class PageTableWalker;

struct RawProcessRecord {
    uint64_t    eprocess_va = 0;
    uint32_t    pid         = 0;
    std::string image_name;         // truncated at first NUL (max 15 chars)
    uint32_t    parent_pid   = 0;
};

struct WalkResult {
    bool                          ok = false;
    std::string                   error;
    std::vector<RawProcessRecord> processes;
    std::size_t                   iterations = 0;
};

WalkResult walk_active_process_list(const PageTableWalker& walker,
                                    uint64_t ps_active_process_head_va,
                                    const EprocessOffsets& offsets,
                                    std::size_t max_iter = 8192);

}  // namespace angelia::memforensics
