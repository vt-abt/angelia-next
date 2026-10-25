#include "memforensics/PhysicalMemoryReader.h"

#include <windows.h>
#include <mindumpdef.h>

#include <fmt/format.h>

#include <algorithm>
#include <cstring>

#include "memforensics/DumpIdentify.h"

namespace angelia::memforensics {

namespace {

// DUMP_HEADER64 layout (Windows 10/11 x64). Offsets confirmed against
// wdbgexts.h and public sources; a mismatch on version halts us rather
// than let a wrong offset produce plausible-looking garbage.
inline constexpr std::size_t kDumpHeaderSize          = 0x2000;   // header eats first 8 KiB
inline constexpr std::size_t kOffPhysMemBlock         = 0x88;

// PHYSICAL_MEMORY_DESCRIPTOR:
//   u32 NumberOfRuns
//   u32 _pad
//   u64 NumberOfPages
//   PHYSICAL_MEMORY_RUN[NumberOfRuns]
inline constexpr std::size_t kPhysDescRunsOffset      = 16;   // relative to descriptor start
// PHYSICAL_MEMORY_RUN:
//   u64 BasePage
//   u64 PageCount
inline constexpr std::size_t kRunEntrySize            = 16;

inline constexpr uint64_t kPageSize = 0x1000;

}  // namespace

PhysicalMemoryReader::~PhysicalMemoryReader() { close(); }

bool PhysicalMemoryReader::is_open() const noexcept {
    return from_buffer_ ? !buffer_.empty()
                        : (file_handle_ && file_handle_ != INVALID_HANDLE_VALUE);
}

void PhysicalMemoryReader::close() {
    if (file_handle_ && file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(reinterpret_cast<HANDLE>(file_handle_));
        file_handle_ = nullptr;
    }
    buffer_.clear();
    from_buffer_ = false;
    runs_.clear();
    header_ = {};
    last_error_.clear();
    file_size_ = 0;
}

bool PhysicalMemoryReader::open(const std::filesystem::path& path) {
    close();

    // Fast-fail on non-PAGEDU64 files with a helpful message from P0.2.
    auto info = identify(path);
    if (info.kind != DumpKind::HeaderBearing64) {
        last_error_ = fmt::format(
            "physical reader wants a PAGEDU64 dump; {} — {}",
            to_string(info.kind), info.rejection_reason);
        return false;
    }
    if (info.file_size < kDumpHeaderSize) {
        last_error_ = "PAGEDU64 header is truncated (needs 8192 bytes)";
        return false;
    }
    file_size_ = info.file_size;

    HANDLE h = CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        last_error_ = fmt::format("CreateFileW failed on {} (GetLastError=0x{:08x})",
                                  path.string(), static_cast<uint32_t>(GetLastError()));
        return false;
    }
    file_handle_ = h;

    // Read the header eagerly. 8 KiB is nothing.
    std::vector<uint8_t> hdr(kDumpHeaderSize);
    DWORD got = 0;
    if (!ReadFile(h, hdr.data(), kDumpHeaderSize, &got, nullptr) || got != kDumpHeaderSize) {
        last_error_ = fmt::format("short header read on {}", path.string());
        const auto error=last_error_;
        close();
        last_error_=error;
        return false;
    }
    if (!parse_header(hdr.data(), hdr.size()) || !parse_runs(hdr.data(), hdr.size())) {
        const auto error=last_error_;
        close();
        last_error_=error;
        return false;
    }
    return true;
}

void PhysicalMemoryReader::open_from_buffer(std::vector<uint8_t> image,
                                            const DumpHeader& hdr,
                                            std::vector<MemoryRun> runs) {
    close();
    buffer_      = std::move(image);
    from_buffer_ = true;
    header_      = hdr;
    runs_        = std::move(runs);
    std::sort(runs_.begin(), runs_.end(),
              [](const MemoryRun& a, const MemoryRun& b) { return a.phys_start < b.phys_start; });
}

bool PhysicalMemoryReader::parse_header(const uint8_t* raw, std::size_t sz) {
    // Signature check is P0.2 territory but repeat it locally for
    // buffer-based tests that skip open().
    if (sz < 0x40 ||
        std::memcmp(raw + dump64::kOffSignature, "PAGE",   4) != 0 ||
        std::memcmp(raw + dump64::kOffValidDump, "DU64",   4) != 0) {
        last_error_ = "not a PAGEDU64 dump";
        return false;
    }
    auto rd = [raw](std::size_t off) {
        uint64_t v; std::memcpy(&v, raw + off, sizeof(v)); return v;
    };
    auto rd32 = [raw](std::size_t off) {
        uint32_t v; std::memcpy(&v, raw + off, sizeof(v)); return v;
    };
    header_.directory_table_base   = rd(dump64::kOffDirectoryTableBase);
    header_.pfn_database           = rd(dump64::kOffPfnDatabase);
    header_.ps_loaded_module_list  = rd(dump64::kOffPsLoadedModuleList);
    header_.ps_active_process_head = rd(dump64::kOffPsActiveProcessHead);
    header_.machine_image_type     = rd32(dump64::kOffMachineImageType);
    header_.number_processors      = rd32(dump64::kOffMachineImageType + 4);
    header_.bugcheck_code          = rd32(dump64::kOffMachineImageType + 8);
    header_.dump_type              = rd32(offsetof(DUMP_HEADER64, DumpType));
    header_.system_time_100ns      = rd(offsetof(DUMP_HEADER64, SystemTime));
    if (header_.machine_image_type != IMAGE_FILE_MACHINE_AMD64) {
        last_error_ = "PAGEDU64 dump is not x64 (AMD64)";
        return false;
    }
    if (!header_.directory_table_base || !header_.ps_active_process_head) {
        last_error_ = "PAGEDU64 header lacks DTB or PsActiveProcessHead";
        return false;
    }
    return true;
}

bool PhysicalMemoryReader::parse_runs(const uint8_t* raw, std::size_t sz) {
    if (sz < kOffPhysMemBlock + kPhysDescRunsOffset) {
        last_error_ = "header too small for physical-memory descriptor";
        return false;
    }
    uint32_t n_runs = 0;
    std::memcpy(&n_runs, raw + kOffPhysMemBlock, sizeof(n_runs));
    uint64_t declared_pages=0;
    std::memcpy(&declared_pages,raw+kOffPhysMemBlock+8,sizeof(declared_pages));
    if (n_runs == 0 || n_runs > 65536) {
        last_error_ = fmt::format("implausible NumberOfRuns={}", n_runs);
        return false;
    }
    const std::size_t runs_start = kOffPhysMemBlock + kPhysDescRunsOffset;
    if (runs_start + n_runs * kRunEntrySize > sz) {
        last_error_ = "runs table overflows header";
        return false;
    }
    runs_.reserve(n_runs);
    uint64_t file_off = kDumpHeaderSize;
    uint64_t counted_pages=0;
    for (uint32_t i = 0; i < n_runs; ++i) {
        uint64_t base_page = 0, page_count = 0;
        std::memcpy(&base_page,  raw + runs_start + i * kRunEntrySize,     8);
        std::memcpy(&page_count, raw + runs_start + i * kRunEntrySize + 8, 8);
        if (page_count==0 || page_count>(UINT64_MAX-file_off)/kPageSize ||
            base_page>UINT64_MAX/kPageSize ||
            page_count>UINT64_MAX/kPageSize-base_page ||
            counted_pages>UINT64_MAX-page_count) {
            last_error_ = "invalid physical-memory run size";
            return false;
        }
        counted_pages += page_count;
        MemoryRun r;
        r.phys_start  = base_page * kPageSize;
        r.length      = page_count * kPageSize;
        r.file_offset = file_off;
        runs_.push_back(r);
        file_off += r.length;
        if (file_off>file_size_) {
            last_error_ = "physical-memory runs extend past end of dump file";
            return false;
        }
    }
    if (counted_pages!=declared_pages) {
        last_error_ = "physical-memory run page count disagrees with dump header";
        return false;
    }
    std::sort(runs_.begin(),runs_.end(),
              [](const MemoryRun& a,const MemoryRun& b){return a.phys_start<b.phys_start;});
    for (std::size_t i=1;i<runs_.size();++i)
        if (runs_[i-1].phys_start+runs_[i-1].length>runs_[i].phys_start) {
            last_error_ = "overlapping physical-memory runs";
            return false;
        }
    return true;
}

std::size_t PhysicalMemoryReader::read(uint64_t pa, void* dst, std::size_t n) noexcept {
    if (n == 0 || !is_open()) return 0;
    std::size_t total = 0;
    auto* out = static_cast<uint8_t*>(dst);
    while (n > 0) {
        // Find the run containing pa. Runs are sorted by phys_start.
        auto it = std::upper_bound(runs_.begin(), runs_.end(), pa,
            [](uint64_t p, const MemoryRun& r) { return p < r.phys_start; });
        if (it == runs_.begin()) return total;                     // pa before any run
        --it;
        const uint64_t rel = pa - it->phys_start;
        if (rel >= it->length) return total;                       // pa in a hole
        const std::size_t take = static_cast<std::size_t>(
            std::min<uint64_t>(n, it->length - rel));
        const uint64_t src_off = it->file_offset + rel;

        if (from_buffer_) {
            if (src_off + take > buffer_.size()) return total;
            std::memcpy(out, buffer_.data() + src_off, take);
        } else {
            LARGE_INTEGER pos; pos.QuadPart = static_cast<LONGLONG>(src_off);
            if (!SetFilePointerEx(reinterpret_cast<HANDLE>(file_handle_), pos, nullptr, FILE_BEGIN))
                return total;
            DWORD got = 0;
            if (!ReadFile(reinterpret_cast<HANDLE>(file_handle_), out,
                          static_cast<DWORD>(take), &got, nullptr) || got != take)
                return total + got;
        }
        pa    += take;
        out   += take;
        n     -= take;
        total += take;
    }
    return total;
}

}  // namespace angelia::memforensics
