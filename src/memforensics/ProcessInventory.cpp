#include "memforensics/ProcessInventory.h"

#include <nlohmann/json.hpp>

#include <fmt/format.h>

#include <algorithm>
#include <unordered_map>

using json = nlohmann::json;

namespace angelia::memforensics {

Inventory build_inventory(const std::vector<RawProcessRecord>& raw,
                          const LiveSnapshot* live) {
    Inventory inv;

    // First pass: raw walk entries — everything we saw on the list.
    std::unordered_map<uint32_t, std::size_t> by_pid;
    for (const auto& r : raw) {
        InventoryEntry e;
        e.pid              = r.pid;
        e.image_raw        = r.image_name;
        e.eprocess_va      = r.eprocess_va;
        e.parent_pid       = r.parent_pid;
        e.seen_in_raw_walk = true;
        by_pid[r.pid]      = inv.entries.size();
        inv.entries.push_back(std::move(e));
    }

    // Overlay the live snapshot. A process may start or exit between the
    // dump and this snapshot, so differences are marked for review only.
    if (live) {
        for (const auto& lp : live->processes) {
            auto it = by_pid.find(lp.pid);
            if (it == by_pid.end()) {
                InventoryEntry e;
                e.pid          = lp.pid;
                e.image_live   = lp.image;
                e.seen_in_live = true;
                by_pid[lp.pid] = inv.entries.size();
                inv.entries.push_back(std::move(e));
            } else {
                inv.entries[it->second].image_live   = lp.image;
                inv.entries[it->second].seen_in_live = true;
            }
        }
        // Compute comparison categories without claiming concealment.
        for (auto& e : inv.entries) {
            e.raw_only = e.seen_in_raw_walk && !e.seen_in_live;
            e.snapshot_only = e.seen_in_live && !e.seen_in_raw_walk;
        }
    }

    std::sort(inv.entries.begin(), inv.entries.end(),
              [](const InventoryEntry& a, const InventoryEntry& b) {
                  return a.pid < b.pid;
              });
    return inv;
}

std::string to_json(const Inventory& inv) {
    json j;
    j["raw_only_count"] = inv.raw_only_count();
    j["comparison_caveat"] = "Dump and live snapshot are captured at different times; a difference is not proof of a hidden process.";
    j["entries"] = json::array();
    for (const auto& e : inv.entries) {
        j["entries"].push_back({
            {"pid",              e.pid},
            {"image_raw",        e.image_raw},
            {"image_live",       e.image_live},
            {"eprocess_va",      fmt::format("0x{:016x}", e.eprocess_va)},
            {"parent_pid",       e.parent_pid},
            {"seen_in_raw_walk", e.seen_in_raw_walk},
            {"seen_in_live",     e.seen_in_live},
            {"raw_only",         e.raw_only},
            {"snapshot_only",    e.snapshot_only},
        });
    }
    return j.dump(2);
}

}  // namespace angelia::memforensics
