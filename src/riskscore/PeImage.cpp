#include "riskscore/PeImage.h"

#include <windows.h>

#include <fmt/format.h>

#include <cstring>

namespace angelia::riskscore {

PeImage::~PeImage() { close(); }

void PeImage::close() {
    if (base_) {
        UnmapViewOfFile(base_);
        base_ = nullptr;
    }
    if (h_map_) {
        CloseHandle(reinterpret_cast<HANDLE>(h_map_));
        h_map_ = nullptr;
    }
    if (h_file_ && h_file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(reinterpret_cast<HANDLE>(h_file_));
        h_file_ = nullptr;
    }
    size_ = 0;
    sections_.clear();
    directories_.clear();
    last_error_.clear();
}

bool PeImage::open(const std::filesystem::path& p) {
    close();
    path_ = p;

    HANDLE hFile = CreateFileW(p.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        last_error_ = fmt::format("CreateFileW({}) failed (GetLastError=0x{:08x})",
                                   p.string(), static_cast<uint32_t>(GetLastError()));
        return false;
    }
    h_file_ = hFile;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER))) {
        last_error_ = "file too small for a PE";
        close();
        return false;
    }
    size_ = static_cast<std::size_t>(sz.QuadPart);

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        last_error_ = fmt::format("CreateFileMapping failed (GetLastError=0x{:08x})",
                                   static_cast<uint32_t>(GetLastError()));
        close();
        return false;
    }
    h_map_ = hMap;

    LPVOID view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        last_error_ = fmt::format("MapViewOfFile failed (GetLastError=0x{:08x})",
                                   static_cast<uint32_t>(GetLastError()));
        close();
        return false;
    }
    base_ = static_cast<const uint8_t*>(view);

    // Validate MZ + PE\0\0.
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        last_error_ = "not an MZ file";
        close();
        return false;
    }
    if (dos->e_lfanew < 0 || static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size_) {
        last_error_ = "e_lfanew out of range";
        close();
        return false;
    }
    const uint8_t* nt_raw = base_ + dos->e_lfanew;
    uint32_t sig = 0; std::memcpy(&sig, nt_raw, 4);
    if (sig != IMAGE_NT_SIGNATURE) {
        last_error_ = "not a PE (missing PE\\0\\0 signature)";
        close();
        return false;
    }

    IMAGE_FILE_HEADER fh{};
    std::memcpy(&fh, nt_raw + 4, sizeof(fh));
    machine_         = fh.Machine;
    timestamp_       = fh.TimeDateStamp;
    characteristics_ = fh.Characteristics;

    // Choose OptionalHeader flavour by magic.
    const uint8_t* oh = nt_raw + 4 + sizeof(IMAGE_FILE_HEADER);
    if (oh + 2 > base_ + size_) { last_error_ = "truncated at optional header"; close(); return false; }
    uint16_t magic = 0; std::memcpy(&magic, oh, sizeof(magic));

    uint32_t num_data_dirs = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (oh + sizeof(IMAGE_OPTIONAL_HEADER64) > base_ + size_) {
            last_error_ = "truncated at opt64 header"; close(); return false;
        }
        IMAGE_OPTIONAL_HEADER64 opt{};
        std::memcpy(&opt, oh, sizeof(opt));
        is_pe64_             = true;
        image_base_          = opt.ImageBase;
        size_of_image_       = opt.SizeOfImage;
        aoep_                = opt.AddressOfEntryPoint;
        dll_characteristics_ = opt.DllCharacteristics;
        num_data_dirs        = opt.NumberOfRvaAndSizes;
        directories_.reserve(num_data_dirs);
        for (uint32_t i = 0; i < num_data_dirs && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            directories_.push_back({opt.DataDirectory[i].VirtualAddress,
                                    opt.DataDirectory[i].Size});
        }
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (oh + sizeof(IMAGE_OPTIONAL_HEADER32) > base_ + size_) {
            last_error_ = "truncated at opt32 header"; close(); return false;
        }
        IMAGE_OPTIONAL_HEADER32 opt{};
        std::memcpy(&opt, oh, sizeof(opt));
        is_pe64_             = false;
        image_base_          = opt.ImageBase;
        size_of_image_       = opt.SizeOfImage;
        aoep_                = opt.AddressOfEntryPoint;
        dll_characteristics_ = opt.DllCharacteristics;
        num_data_dirs        = opt.NumberOfRvaAndSizes;
        directories_.reserve(num_data_dirs);
        for (uint32_t i = 0; i < num_data_dirs && i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
            directories_.push_back({opt.DataDirectory[i].VirtualAddress,
                                    opt.DataDirectory[i].Size});
        }
    } else {
        last_error_ = fmt::format("unknown optional-header magic 0x{:04x}", magic);
        close();
        return false;
    }

    const std::size_t oh_size = is_pe64_ ? sizeof(IMAGE_OPTIONAL_HEADER64)
                                         : sizeof(IMAGE_OPTIONAL_HEADER32);
    const IMAGE_SECTION_HEADER* sh =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(oh + oh_size);
    if (reinterpret_cast<const uint8_t*>(sh) + fh.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) > base_ + size_) {
        last_error_ = "section table extends past EOF";
        close();
        return false;
    }
    sections_.reserve(fh.NumberOfSections);
    for (uint16_t i = 0; i < fh.NumberOfSections; ++i) {
        PeSection s;
        char n[9] = {}; std::memcpy(n, sh[i].Name, 8);
        s.name             = n;
        s.virtual_size     = sh[i].Misc.VirtualSize;
        s.virtual_address  = sh[i].VirtualAddress;
        s.raw_size         = sh[i].SizeOfRawData;
        s.raw_pointer      = sh[i].PointerToRawData;
        s.characteristics  = sh[i].Characteristics;
        sections_.push_back(std::move(s));
    }
    return true;
}

PeImage::Dir PeImage::directory(unsigned idx) const noexcept {
    if (idx >= directories_.size()) return {0, 0};
    return directories_[idx];
}

std::string_view PeImage::raw(const PeSection& s) const noexcept {
    if (s.raw_size == 0) return {};
    if (s.raw_pointer + s.raw_size > size_) return {};
    return {reinterpret_cast<const char*>(base_ + s.raw_pointer), s.raw_size};
}

const uint8_t* PeImage::at_rva(uint32_t rva, std::size_t need) const noexcept {
    for (const auto& s : sections_) {
        if (rva >= s.virtual_address && rva < s.virtual_address + std::max(s.virtual_size, s.raw_size)) {
            const uint32_t delta = rva - s.virtual_address;
            if (delta >= s.raw_size) return nullptr;   // in the uninit tail
            if (delta + need > s.raw_size) return nullptr;
            if (s.raw_pointer + delta + need > size_) return nullptr;
            return base_ + s.raw_pointer + delta;
        }
    }
    return nullptr;
}

std::string_view PeImage::cstr_at_rva(uint32_t rva, std::size_t max_len) const noexcept {
    const uint8_t* p = at_rva(rva, 1);
    if (!p) return {};
    // Cap by section boundary — at_rva already gave us "safe to read 1
    // byte"; extend byte-by-byte within the file mapping.
    const uint8_t* end = base_ + size_;
    std::size_t n = 0;
    while (p + n < end && n < max_len && p[n] != 0) ++n;
    return {reinterpret_cast<const char*>(p), n};
}

}  // namespace angelia::riskscore
