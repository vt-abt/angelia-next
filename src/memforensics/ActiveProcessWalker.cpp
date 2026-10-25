#include "memforensics/ActiveProcessWalker.h"

#include "memforensics/PageTableWalker.h"

#include <fmt/format.h>

#include <cstring>
#include <unordered_set>

namespace angelia::memforensics {

namespace {

std::string trim_image(const char* raw, std::size_t cap) {
    // ImageFileName is a NUL-padded CHAR array up to 15 chars.
    std::size_t n = 0;
    while (n < cap && raw[n] != '\0') ++n;
    // Reject non-printable garbage so a bad walk doesn't inject
    // control chars into downstream reports.
    for (std::size_t i = 0; i < n; ++i) {
        auto c = static_cast<unsigned char>(raw[i]);
        if (c < 0x20 || c > 0x7E) return {};
    }
    return std::string(raw, n);
}

}  // namespace

WalkResult walk_active_process_list(const PageTableWalker& walker,
                                    uint64_t head_va,
                                    const EprocessOffsets& off,
                                    std::size_t max_iter) {
    WalkResult r;
    if (!off.resolved) { r.error = "offsets not resolved"; return r; }
    if (head_va == 0)  { r.error = "PsActiveProcessHead virtual address is 0"; return r; }

    // Head is a LIST_ENTRY sitting in kernel data. Flink points at the
    // first _EPROCESS's ActiveProcessLinks field. When Flink == head_va
    // we've cycled back to the sentinel and the walk is done.
    auto flink_opt = walker.read_virtual_pod<uint64_t>(head_va);
    if (!flink_opt) { r.error = "cannot read PsActiveProcessHead.Flink"; return r; }

    std::unordered_set<uint64_t> seen;   // cycle detector
    uint64_t cur = *flink_opt;

    while (r.iterations < max_iter && cur != 0 && cur != head_va) {
        if (!seen.insert(cur).second) {
            r.error = fmt::format("walk cycled at Flink=0x{:x}", cur);
            r.ok = true;   // still return what we saw before the cycle
            return r;
        }

        const uint64_t eprocess = cur - off.active_process_links;

        RawProcessRecord rec;
        rec.eprocess_va = eprocess;

        // UniqueProcessId — kernel HANDLE, 8 bytes on x64.
        if (auto id = walker.read_virtual_pod<uint64_t>(eprocess + off.unique_process_id)) {
            rec.pid = static_cast<uint32_t>(*id);
        }

        // ImageFileName — 15 bytes typically.
        char imgbuf[16] = {};
        if (walker.read_virtual(eprocess + off.image_file_name,
                                 imgbuf, sizeof(imgbuf) - 1) > 0) {
            rec.image_name = trim_image(imgbuf, sizeof(imgbuf) - 1);
        }

        // Parent pid, if the resolver had that offset.
        if (off.inherited_from) {
            if (auto p = walker.read_virtual_pod<uint64_t>(eprocess + off.inherited_from))
                rec.parent_pid = static_cast<uint32_t>(*p);
        }

        r.processes.push_back(std::move(rec));
        ++r.iterations;

        // Move to next Flink.
        auto next = walker.read_virtual_pod<uint64_t>(cur);
        if (!next) { r.error = fmt::format("cannot read Flink at 0x{:x}", cur); r.ok = true; return r; }
        cur = *next;
    }
    if (r.iterations == max_iter && cur != head_va) {
        r.error = fmt::format("walk halted at max_iter={}", max_iter);
    }
    r.ok = true;
    return r;
}

}  // namespace angelia::memforensics
