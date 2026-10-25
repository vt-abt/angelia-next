#pragma once

// Read-only PE image wrapper. Maps the file with FILE_MAP_READ +
// SEC_COMMIT (not SEC_IMAGE — we want the on-disk layout so RVAs need
// manual translation to file offsets). Owns the mapping; every accessor
// hands out non-owning views into it. Never modifies the file.
//
// Deliberate scope: enough of the PE machinery to feed the static
// scorer — section table, data directories, import table. No relocation
// handling, no delay-imports (add when a rule needs them).

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace angelia::riskscore {

struct PeSection {
    std::string name;         // truncated to 8 ASCII chars per PE spec
    uint32_t    virtual_size;
    uint32_t    virtual_address;
    uint32_t    raw_size;
    uint32_t    raw_pointer;
    uint32_t    characteristics;
};

class PeImage {
public:
    PeImage() = default;
    ~PeImage();
    PeImage(const PeImage&)            = delete;
    PeImage& operator=(const PeImage&) = delete;

    bool open(const std::filesystem::path& path);
    void close();

    bool is64() const noexcept { return is_pe64_; }
    uint16_t machine() const noexcept { return machine_; }
    uint64_t image_base() const noexcept { return image_base_; }
    uint32_t size_of_image() const noexcept { return size_of_image_; }
    uint32_t timestamp() const noexcept { return timestamp_; }
    uint16_t characteristics() const noexcept { return characteristics_; }
    uint16_t dll_characteristics() const noexcept { return dll_characteristics_; }
    uint32_t address_of_entry_point() const noexcept { return aoep_; }

    const std::vector<PeSection>& sections() const noexcept { return sections_; }

    // Data-directory access. Returns {rva, size}. rva == 0 means absent.
    struct Dir { uint32_t rva; uint32_t size; };
    Dir directory(unsigned idx) const noexcept;

    // Raw byte-view of a section by its on-disk range. Empty when the
    // section has no raw bytes (e.g. uninitialised .bss-alike).
    std::string_view raw(const PeSection& s) const noexcept;

    // Translate an RVA to a pointer into the on-disk mapping. Returns
    // nullptr if the RVA is outside any section's raw range.
    const uint8_t* at_rva(uint32_t rva, std::size_t need = 1) const noexcept;

    // C-string read at an RVA. Truncates at max_len; empty if bad RVA.
    std::string_view cstr_at_rva(uint32_t rva, std::size_t max_len = 512) const noexcept;

    const std::filesystem::path& path() const noexcept { return path_; }
    const std::string& last_error() const noexcept { return last_error_; }

private:
    std::filesystem::path path_;
    void*        h_file_ = nullptr;      // HANDLE
    void*        h_map_  = nullptr;
    const uint8_t* base_ = nullptr;
    std::size_t  size_   = 0;

    bool     is_pe64_ = false;
    uint16_t machine_ = 0;
    uint64_t image_base_ = 0;
    uint32_t size_of_image_ = 0;
    uint32_t timestamp_ = 0;
    uint16_t characteristics_ = 0;
    uint16_t dll_characteristics_ = 0;
    uint32_t aoep_ = 0;

    std::vector<PeSection>  sections_;
    std::vector<Dir>        directories_;
    std::string             last_error_;
};

}  // namespace angelia::riskscore
