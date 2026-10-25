// Generates a small header-bearing PAGEDU64 dump for testing the
// PhysicalMemoryReader + PageTableWalker + ActiveProcessLinks walker
// without needing a real Windows crash dump. Not a substitute for
// running against a real acquisition — but it lets the parser code get
// exercised end-to-end from unit tests.
//
// Layout (all physical addresses):
//   0x0000_0000 .. 0x0000_1FFF   dump header (fabricated)
//   0x0000_2000 .. 0x0000_2FFF   PML4 (single entry to PDPT)
//   0x0000_3000 .. 0x0000_3FFF   PDPT (single entry to PD)
//   0x0000_4000 .. 0x0000_4FFF   PD   (single entry to PT)
//   0x0000_5000 .. 0x0000_5FFF   PT   (mapping VA 0xFFFF_F800_0000_0000 -> phys 0x6000)
//   0x0000_6000 .. 0x0000_6FFF   PsActiveProcessHead + two fake _EPROCESS entries
//
// The tool writes the whole thing as one file; DUMP_HEADER64 fields at
// their documented offsets, single memory run covering [0, 0x8000).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "memforensics/DumpIdentify.h"

using namespace angelia::memforensics;

namespace {

constexpr std::size_t kHeaderSize = 0x2000;
constexpr std::size_t kImageSize  = 0x8000;    // 32 KiB total

void put64(std::vector<uint8_t>& b, std::size_t off, uint64_t v) {
    std::memcpy(b.data() + off, &v, sizeof(v));
}
void put32(std::vector<uint8_t>& b, std::size_t off, uint32_t v) {
    std::memcpy(b.data() + off, &v, sizeof(v));
}

}  // namespace

int angelia_cli_run_gen_synth_dump(int argc, char** argv) {
    if (argc != 2) { std::fprintf(stderr, "usage: gen_synthetic_dump <out.dmp>\n"); return 2; }

    std::vector<uint8_t> file(kHeaderSize + (kImageSize - kHeaderSize), 0);

    // ---- DUMP_HEADER64 (first 8 KiB) ----
    std::memcpy(file.data() + dump64::kOffSignature, "PAGE", 4);
    std::memcpy(file.data() + dump64::kOffValidDump, "DU64", 4);
    put32(file, 8,  10);   // MajorVersion
    put32(file, 12,  0);   // MinorVersion
    put64(file, dump64::kOffDirectoryTableBase,  0x2000);              // CR3 -> PML4 at 0x2000
    put64(file, dump64::kOffPfnDatabase,         0);
    put64(file, dump64::kOffPsLoadedModuleList,  0);
    put64(file, dump64::kOffPsActiveProcessHead, 0xFFFF'F800'0000'0000ull);
    put32(file, dump64::kOffMachineImageType,    0x8664);              // AMD64
    put32(file, dump64::kOffMachineImageType + 4, 1);                  // NumberProcessors
    put32(file, dump64::kOffMachineImageType + 8, 0);                  // BugCheckCode

    // ---- PHYSICAL_MEMORY_DESCRIPTOR at 0x88 ----
    // One run starting at phys page 2 (i.e. phys 0x2000). That way the
    // file layout — header at 0..0x1FFF, memory content at 0x2000+ —
    // corresponds directly to phys addresses 0x2000+ under the reader's
    // "file_offset = header_size + sum(prior_run_bytes) + (pa -
    // run_phys_start)" translation.
    constexpr uint64_t kRunBasePage  = 2;                      // phys 0x2000
    constexpr uint64_t kRunPageCount = (kImageSize - 0x2000) / 0x1000;
    put32(file, 0x88,      1);
    put32(file, 0x88 + 4,  0);
    put64(file, 0x88 + 8,  kRunPageCount);
    put64(file, 0x88 + 16, kRunBasePage);
    put64(file, 0x88 + 24, kRunPageCount);

    // ---- Page tables ----
    // PML4[idx of 0xFFFFF80000000000] -> PDPT at 0x3000
    // 0xFFFFF80000000000 bits [47..39] = 0x1F0 = 496
    // Entry format: (phys_addr) | Present(bit0)
    const uint64_t PRESENT = 1;
    put64(file, 0x2000 + 496 * 8, (0x3000ull) | PRESENT);
    // PDPT[bits 38..30 = 0] -> PD at 0x4000
    put64(file, 0x3000 + 0 * 8, (0x4000ull) | PRESENT);
    // PD[bits 29..21 = 0] -> PT at 0x5000
    put64(file, 0x4000 + 0 * 8, (0x5000ull) | PRESENT);
    // PT[bits 20..12 = 0] -> physical page 0x6000
    put64(file, 0x5000 + 0 * 8, (0x6000ull) | PRESENT);

    // ---- Fake ActiveProcessHead LIST_ENTRY + two _EPROCESS entries ----
    // We don't need real _EPROCESS layout for the reader/walker unit
    // tests — the ActiveProcessWalker test picks up from here in Stage
    // 2's next slice. For now: put a well-known sentinel at phys 0x6000
    // so a page-walk read for VA 0xFFFF_F800_0000_0000 lands on it.
    constexpr uint64_t kSentinel = 0xDEADBEEFCAFEBABEull;
    put64(file, 0x6000, kSentinel);

    std::ofstream f(argv[1], std::ios::binary | std::ios::trunc);
    if (!f) { std::fprintf(stderr, "cannot open %s\n", argv[1]); return 1; }
    f.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    std::fprintf(stderr, "wrote %zu bytes to %s\n", file.size(), argv[1]);
    return 0;
}
