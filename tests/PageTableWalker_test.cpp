#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

#include "memforensics/PageTableWalker.h"
#include "memforensics/PhysicalMemoryReader.h"
#include "memforensics/DumpIdentify.h"

using namespace angelia::memforensics;

namespace {

// Build a minimal synthetic dump in-memory and drive it through the same
// reader / walker code the real tool uses. This avoids the CI dependency
// on a Windows crash dump on disk.
struct SynthDump {
    std::vector<uint8_t> image;
    DumpHeader           hdr{};
    std::vector<MemoryRun> runs;
};

SynthDump make_synth() {
    constexpr std::size_t kImage = 0x8000;
    SynthDump s;
    s.image.assign(kImage, 0);

    auto put64 = [&](std::size_t off, uint64_t v) {
        std::memcpy(s.image.data() + off, &v, sizeof(v));
    };

    // Header fields we care about; we set them directly and also mirror
    // them into `hdr` because the buffer-load path lets us bypass parsing.
    std::memcpy(s.image.data() + dump64::kOffSignature, "PAGE", 4);
    std::memcpy(s.image.data() + dump64::kOffValidDump, "DU64", 4);
    put64(dump64::kOffDirectoryTableBase, 0x2000);
    put64(dump64::kOffPsActiveProcessHead, 0xFFFF'F800'0000'0000ull);

    s.hdr.directory_table_base   = 0x2000;
    s.hdr.ps_active_process_head = 0xFFFF'F800'0000'0000ull;

    // Page tables: PML4 -> PDPT -> PD -> PT -> phys 0x6000
    const uint64_t PRESENT = 1;
    put64(0x2000 + 496 * 8, 0x3000ull | PRESENT);   // PML4[496]
    put64(0x3000 + 0   * 8, 0x4000ull | PRESENT);   // PDPT[0]
    put64(0x4000 + 0   * 8, 0x5000ull | PRESENT);   // PD[0]
    put64(0x5000 + 0   * 8, 0x6000ull | PRESENT);   // PT[0]

    // Sentinel bytes at phys 0x6000
    put64(0x6000, 0xDEADBEEFCAFEBABEull);

    // Single memory run covering the whole image, file_offset == 0
    // because for the buffer-load path we don't have a header-skip.
    MemoryRun r;
    r.phys_start  = 0;
    r.length      = kImage;
    r.file_offset = 0;
    s.runs.push_back(r);
    return s;
}

TEST(PageTableWalker, Translates4KPageAtCanonicalKernelAddress) {
    auto s = make_synth();
    PhysicalMemoryReader phys;
    phys.open_from_buffer(std::move(s.image), s.hdr, s.runs);

    PageTableWalker walker(phys, s.hdr.directory_table_base);
    const uint64_t va = 0xFFFF'F800'0000'0000ull;
    auto pa = walker.translate(va);
    ASSERT_TRUE(pa.has_value());
    EXPECT_EQ(*pa, 0x6000u);
}

TEST(PageTableWalker, ReadVirtualCopiesSentinel) {
    auto s = make_synth();
    PhysicalMemoryReader phys;
    phys.open_from_buffer(std::move(s.image), s.hdr, s.runs);

    PageTableWalker walker(phys, s.hdr.directory_table_base);
    auto v = walker.read_virtual_pod<uint64_t>(0xFFFF'F800'0000'0000ull);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0xDEADBEEFCAFEBABEull);
}

TEST(PageTableWalker, ReturnsNulloptOnUnmappedVA) {
    auto s = make_synth();
    PhysicalMemoryReader phys;
    phys.open_from_buffer(std::move(s.image), s.hdr, s.runs);

    PageTableWalker walker(phys, s.hdr.directory_table_base);
    // A VA that walks into a PML4 entry we never populated.
    auto pa = walker.translate(0x0000'0000'0010'0000ull);
    EXPECT_FALSE(pa.has_value());
}

// End-to-end regression for the runs-table file-offset math that the
// buffer-load path bypasses. We write a valid synthetic PAGEDU64 to a
// temp file, then open() and walk it just like a real dump.
TEST(PhysicalMemoryReader, SyntheticDumpRoundTripFromDisk) {
    namespace fs = std::filesystem;
    constexpr std::size_t kImage = 0x8000;
    std::vector<uint8_t> f(kImage, 0);
    auto put32 = [&](std::size_t off, uint32_t v){ std::memcpy(f.data()+off,&v,sizeof(v)); };
    auto put64 = [&](std::size_t off, uint64_t v){ std::memcpy(f.data()+off,&v,sizeof(v)); };

    std::memcpy(f.data() + dump64::kOffSignature, "PAGE", 4);
    std::memcpy(f.data() + dump64::kOffValidDump, "DU64", 4);
    put64(dump64::kOffDirectoryTableBase, 0x2000);
    put64(dump64::kOffPsActiveProcessHead, 0xFFFF'F800'0000'0000ull);
    put32(dump64::kOffMachineImageType, 0x8664);

    // Run[0] starts at phys page 2 so file[0x2000..] === phys[0x2000..].
    const uint64_t kRunBasePage  = 2;
    const uint64_t kRunPageCount = (kImage - 0x2000) / 0x1000;
    put32(0x88,      1);
    put32(0x88 + 4,  0);
    put64(0x88 + 8,  kRunPageCount);
    put64(0x88 + 16, kRunBasePage);
    put64(0x88 + 24, kRunPageCount);

    const uint64_t PRESENT = 1;
    put64(0x2000 + 496 * 8, 0x3000ull | PRESENT);   // PML4[496]
    put64(0x3000 + 0   * 8, 0x4000ull | PRESENT);
    put64(0x4000 + 0   * 8, 0x5000ull | PRESENT);
    put64(0x5000 + 0   * 8, 0x6000ull | PRESENT);
    put64(0x6000, 0xDEADBEEFCAFEBABEull);

    fs::path out = fs::temp_directory_path() / "angelia_synth_roundtrip.dmp";
    std::error_code ec; fs::remove(out, ec);
    { std::ofstream w(out, std::ios::binary | std::ios::trunc);
      w.write(reinterpret_cast<const char*>(f.data()), static_cast<std::streamsize>(f.size())); }

    PhysicalMemoryReader phys;
    ASSERT_TRUE(phys.open(out)) << phys.last_error();
    EXPECT_EQ(phys.header().directory_table_base, 0x2000u);

    PageTableWalker walker(phys, phys.header().directory_table_base);
    auto sentinel = walker.read_virtual_pod<uint64_t>(0xFFFF'F800'0000'0000ull);
    ASSERT_TRUE(sentinel.has_value());
    EXPECT_EQ(*sentinel, 0xDEADBEEFCAFEBABEull);

    phys.close();
    fs::remove(out, ec);
}

TEST(PhysicalMemoryReader, RejectsRunExtendingBeyondFile) {
    namespace fs = std::filesystem;
    std::vector<uint8_t> image(0x3000,0);
    auto put32=[&](std::size_t off,uint32_t v){std::memcpy(image.data()+off,&v,sizeof(v));};
    auto put64=[&](std::size_t off,uint64_t v){std::memcpy(image.data()+off,&v,sizeof(v));};
    std::memcpy(image.data()+dump64::kOffSignature,"PAGE",4);
    std::memcpy(image.data()+dump64::kOffValidDump,"DU64",4);
    put64(dump64::kOffDirectoryTableBase,0x2000);
    put64(dump64::kOffPsActiveProcessHead,0xFFFF'F800'0000'0000ull);
    put32(dump64::kOffMachineImageType,0x8664);
    put32(0x88,1); put64(0x90,2); put64(0x98,2); put64(0xA0,2);
    const fs::path path=fs::temp_directory_path()/"angelia_bad_run.dmp";
    {std::ofstream f(path,std::ios::binary|std::ios::trunc);
     f.write(reinterpret_cast<const char*>(image.data()),static_cast<std::streamsize>(image.size()));}
    PhysicalMemoryReader reader;
    EXPECT_FALSE(reader.open(path));
    EXPECT_NE(reader.last_error().find("past end"),std::string::npos);
    std::error_code ec; fs::remove(path,ec);
}

}  // namespace
