#pragma once

// Reader for PAGEDU64 header-bearing crash dumps. Parses the header
// once, walks the PHYSICAL_MEMORY_DESCRIPTOR runs table, then answers
// physical-address reads by translating them to file offsets on demand.
//
// A dump is a sparse image of physical memory: only ranges the OS
// actually had committed to physical frames appear on disk, and each
// range's file offset is (dump_header_size + sum of prior runs' pages).
// So P→file-offset requires walking the runs table until the run
// containing P is found. We cache that walk in a sorted vector of
// {phys_start, file_offset, byte_length} entries so subsequent reads
// are one std::upper_bound away.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace angelia::memforensics {

struct DumpHeader {
    uint64_t directory_table_base   = 0;   // kernel CR3
    uint64_t pfn_database           = 0;
    uint64_t ps_loaded_module_list  = 0;
    uint64_t ps_active_process_head = 0;
    uint32_t machine_image_type     = 0;
    uint32_t number_processors      = 0;
    uint32_t bugcheck_code          = 0;
    uint32_t dump_type              = 0;
    uint64_t system_time_100ns      = 0;
};

struct MemoryRun {
    uint64_t phys_start;    // physical byte address of first byte in run
    uint64_t file_offset;   // where in the dump file the run starts
    uint64_t length;        // bytes
};

class PhysicalMemoryReader {
public:
    PhysicalMemoryReader() = default;
    ~PhysicalMemoryReader();

    PhysicalMemoryReader(const PhysicalMemoryReader&)            = delete;
    PhysicalMemoryReader& operator=(const PhysicalMemoryReader&) = delete;

    // Opens a header-bearing dump. Returns true on success; on failure,
    // last_error() is populated with a diagnostic and no file handles
    // are held.
    bool open(const std::filesystem::path& path);
    void close();

    // Copy up to `n` bytes from physical address `pa` into `dst`. Returns
    // number of bytes actually read (may be less than n if the read
    // straddles unmapped memory). No throws — bad reads return 0.
    std::size_t read(uint64_t pa, void* dst, std::size_t n) noexcept;

    template <typename T>
    std::optional<T> read_pod(uint64_t pa) noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        T v{};
        if (read(pa, &v, sizeof(T)) != sizeof(T)) return std::nullopt;
        return v;
    }

    const DumpHeader&              header() const noexcept { return header_; }
    const std::vector<MemoryRun>&  runs()   const noexcept { return runs_; }
    const std::string&             last_error() const noexcept { return last_error_; }
    bool                            is_open()  const noexcept;

    // For tests: manually seed the reader with a memory image + header.
    // Bypasses file I/O; the reader answers reads from the buffer.
    void open_from_buffer(std::vector<uint8_t> image,
                          const DumpHeader& hdr,
                          std::vector<MemoryRun> runs);

private:
    bool parse_header(const uint8_t* raw, std::size_t sz);
    bool parse_runs(const uint8_t* raw, std::size_t sz);

    // File-backed state (either real file or the buffer for tests).
    void*                       file_handle_ = nullptr;   // Win32 HANDLE (opaque here)
    std::vector<uint8_t>        buffer_;                  // populated only for tests
    bool                        from_buffer_ = false;
    DumpHeader                  header_{};
    std::vector<MemoryRun>      runs_;
    std::string                 last_error_;
    uint64_t                    file_size_ = 0;
};

}  // namespace angelia::memforensics
