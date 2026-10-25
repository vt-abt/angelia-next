#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "memforensics/ActiveProcessWalker.h"
#include "memforensics/DumpIdentify.h"
#include "memforensics/KernelStructureCache.h"
#include "memforensics/LiveProcessSnapshot.h"
#include "memforensics/PageTableWalker.h"
#include "memforensics/PhysicalMemoryReader.h"
#include "memforensics/ProcessInventory.h"

using namespace angelia::memforensics;

namespace {

// Build a synthetic PAGEDU64 dump that contains a two-node
// ActiveProcessLinks list rooted at a fake PsActiveProcessHead. The
// two _EPROCESS shells sit inside the same 4 KiB page we get mapped
// via PT, at fixed offsets we know at test time.
//
// Layout (physical):
//   0x0000-0x1FFF header
//   0x2000-0x2FFF PML4  (entry 0x1F0 -> 0x3000)
//   0x3000-0x3FFF PDPT  (entry 0     -> 0x4000)
//   0x4000-0x4FFF PD    (entry 0     -> 0x5000)
//   0x5000-0x5FFF PT    (entry 0     -> 0x6000)
//   0x6000-0x6FFF payload page holding PsActiveProcessHead + 2 _EPROCESS
//
// Virtual base for the payload: 0xFFFFF80000000000.
//
// Layout inside the payload page:
//   +0x000  PsActiveProcessHead (LIST_ENTRY = 16 bytes)
//   +0x020  Process A _EPROCESS shell
//   +0x100  Process B _EPROCESS shell
//
// _EPROCESS shell layout (only fields we care about):
//   +0x00  ActiveProcessLinks (LIST_ENTRY = 16 bytes)  --> at chosen offset
//   +0x20  UniqueProcessId (u64)
//   +0x30  ImageFileName (16 bytes)
//
// So offsets: apl=0x00, upi=0x20, ifn=0x30 (relative to _EPROCESS start).

struct SynthPack {
    std::vector<uint8_t> image;
    DumpHeader           hdr{};
    std::vector<MemoryRun> runs;
    EprocessOffsets      offsets;
    uint64_t             head_va = 0;
    uint32_t             pid_a = 0, pid_b = 0;
    std::string          name_a, name_b;
};

SynthPack make_pack() {
    constexpr std::size_t kImage = 0x8000;
    SynthPack s;
    s.image.assign(kImage, 0);
    auto put64 = [&](std::size_t off, uint64_t v) {
        std::memcpy(s.image.data() + off, &v, sizeof(v));
    };

    // Header
    std::memcpy(s.image.data() + dump64::kOffSignature, "PAGE", 4);
    std::memcpy(s.image.data() + dump64::kOffValidDump, "DU64", 4);
    put64(dump64::kOffDirectoryTableBase, 0x2000);
    s.head_va = 0xFFFF'F800'0000'0000ull;   // maps to phys 0x6000
    put64(dump64::kOffPsActiveProcessHead, s.head_va);
    s.hdr.directory_table_base   = 0x2000;
    s.hdr.ps_active_process_head = s.head_va;

    // Page tables — same shape as PageTableWalker_test
    const uint64_t PRESENT = 1;
    put64(0x2000 + 496 * 8, 0x3000ull | PRESENT);
    put64(0x3000 + 0   * 8, 0x4000ull | PRESENT);
    put64(0x4000 + 0   * 8, 0x5000ull | PRESENT);
    put64(0x5000 + 0   * 8, 0x6000ull | PRESENT);

    // Offsets within an _EPROCESS shell
    s.offsets.active_process_links = 0x00;
    s.offsets.unique_process_id    = 0x20;
    s.offsets.image_file_name      = 0x30;
    s.offsets.inherited_from       = 0x40;
    s.offsets.resolved             = true;

    // Virtual addresses for the two _EPROCESS shells and the head
    const uint64_t va_head = s.head_va;                // +0x000 in payload
    const uint64_t va_a    = s.head_va + 0x020;        // +0x020 in payload
    const uint64_t va_b    = s.head_va + 0x100;        // +0x100 in payload

    // ActiveProcessLinks fields (each shell's ActiveProcessLinks is at
    // shell + apl_offset). Head is itself a LIST_ENTRY at va_head.
    const uint64_t apl_head_va = va_head;                              // head is the list-entry
    const uint64_t apl_a_va    = va_a + s.offsets.active_process_links;
    const uint64_t apl_b_va    = va_b + s.offsets.active_process_links;

    // Chain: head.Flink -> A.apl; A.Flink -> B.apl; B.Flink -> head
    // (matching Blinks omitted — walker only follows Flink)
    // Physical offsets: subtract 0xFFFF_F800_0000_0000 from VA and add 0x6000.
    auto phys_of = [](uint64_t va) -> std::size_t {
        return 0x6000 + static_cast<std::size_t>(va - 0xFFFF'F800'0000'0000ull);
    };
    // head.Flink = apl_a_va
    put64(phys_of(apl_head_va) + 0, apl_a_va);
    // A.Flink = apl_b_va
    put64(phys_of(apl_a_va) + 0, apl_b_va);
    // B.Flink = apl_head_va (terminate)
    put64(phys_of(apl_b_va) + 0, apl_head_va);

    // PID + image for A
    s.pid_a = 4242; s.name_a = "procA.exe";
    put64(phys_of(va_a + s.offsets.unique_process_id), s.pid_a);
    std::memcpy(s.image.data() + phys_of(va_a + s.offsets.image_file_name),
                s.name_a.data(), s.name_a.size());
    // PID + image for B
    s.pid_b = 9999; s.name_b = "procB.exe";
    put64(phys_of(va_b + s.offsets.unique_process_id), s.pid_b);
    std::memcpy(s.image.data() + phys_of(va_b + s.offsets.image_file_name),
                s.name_b.data(), s.name_b.size());

    // Single memory run covering the whole image in buffer-load mode.
    MemoryRun r;
    r.phys_start  = 0;
    r.length      = kImage;
    r.file_offset = 0;
    s.runs.push_back(r);
    return s;
}

TEST(ActiveProcessWalker, WalksTwoProcessSyntheticList) {
    auto pack = make_pack();
    PhysicalMemoryReader phys;
    phys.open_from_buffer(std::move(pack.image), pack.hdr, pack.runs);
    PageTableWalker pw(phys, pack.hdr.directory_table_base);

    auto res = walk_active_process_list(pw, pack.hdr.ps_active_process_head,
                                        pack.offsets);
    ASSERT_TRUE(res.ok) << res.error;
    ASSERT_EQ(res.processes.size(), 2u);
    EXPECT_EQ(res.processes[0].pid, pack.pid_a);
    EXPECT_EQ(res.processes[0].image_name, pack.name_a);
    EXPECT_EQ(res.processes[1].pid, pack.pid_b);
    EXPECT_EQ(res.processes[1].image_name, pack.name_b);
}

TEST(ProcessInventory, MarksCrossTimeDifferenceForReview) {
    auto pack = make_pack();
    PhysicalMemoryReader phys;
    phys.open_from_buffer(std::move(pack.image), pack.hdr, pack.runs);
    PageTableWalker pw(phys, pack.hdr.directory_table_base);
    auto res = walk_active_process_list(pw, pack.hdr.ps_active_process_head,
                                        pack.offsets);
    ASSERT_TRUE(res.ok);

    // Live snapshot only knows about A; B may have exited between captures.
    LiveSnapshot live;
    live.captured_iso8601_utc = "2026-01-01T00:00:00Z";
    live.processes.push_back({pack.pid_a, "procA.exe"});

    auto inv = build_inventory(res.processes, &live);
    ASSERT_EQ(inv.entries.size(), 2u);
    // Find each pid.
    const InventoryEntry* a = nullptr;
    const InventoryEntry* b = nullptr;
    for (const auto& e : inv.entries) {
        if (e.pid == pack.pid_a) a = &e;
        if (e.pid == pack.pid_b) b = &e;
    }
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);
    EXPECT_TRUE (a->seen_in_raw_walk);
    EXPECT_TRUE (a->seen_in_live);
    EXPECT_FALSE(a->raw_only);
    EXPECT_TRUE (b->seen_in_raw_walk);
    EXPECT_FALSE(b->seen_in_live);
    EXPECT_TRUE (b->raw_only);
    EXPECT_EQ(inv.raw_only_count(), 1u);
}

TEST(KernelStructureCache, RoundTripsViaTempFile) {
    auto path = std::filesystem::temp_directory_path() / "angelia_cache_test.json";
    std::error_code ec; std::filesystem::remove(path, ec);
    {
        KernelStructureCache c(path);
        EprocessOffsets o;
        o.active_process_links = 472;
        o.unique_process_id    = 1088;
        o.image_file_name      = 1512;
        o.inherited_from       = 1568;
        o.resolved             = true;
        c.put_eprocess("ABC123+1", o);
        c.save();
    }
    KernelStructureCache c2(path);
    auto got = c2.get_eprocess("ABC123+1");
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(got->active_process_links, 472u);
    EXPECT_EQ(got->unique_process_id,    1088u);
    EXPECT_EQ(got->image_file_name,      1512u);
    EXPECT_EQ(got->inherited_from,       1568u);
    std::filesystem::remove(path, ec);
}

}  // namespace
