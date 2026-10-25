#include "riskscore/ImportScanner.h"

#include "riskscore/PeImage.h"

#include <windows.h>

#include <fmt/format.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace angelia::riskscore {

namespace {

std::string to_lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return out;
}

}  // namespace

std::vector<ImportEntry> scan_imports(const PeImage& pe, std::size_t max_entries) {
    std::vector<ImportEntry> out;
    const auto imp_dir = pe.directory(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (imp_dir.rva == 0 || imp_dir.size == 0) return out;

    // Walk one IMAGE_IMPORT_DESCRIPTOR at a time; the table ends at a
    // zero-filled terminator entry.
    for (std::size_t di = 0; out.size() < max_entries; ++di) {
        // Bounds check per descriptor.
        const uint32_t rva_here = imp_dir.rva +
            static_cast<uint32_t>(di * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        const auto* di_raw = pe.at_rva(rva_here, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (!di_raw) break;
        IMAGE_IMPORT_DESCRIPTOR desc{};
        std::memcpy(&desc, di_raw, sizeof(desc));
        if (desc.Name == 0 && desc.FirstThunk == 0) break;    // terminator

        auto dll_lc = to_lower(pe.cstr_at_rva(desc.Name));
        if (dll_lc.empty()) continue;

        // Prefer OriginalFirstThunk (INT — preserved after loader binds);
        // fall back to FirstThunk (IAT) which becomes the addresses after
        // load but on-disk still holds the same shape.
        uint32_t thunk_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                     : desc.FirstThunk;
        if (thunk_rva == 0) continue;

        for (std::size_t ti = 0; out.size() < max_entries; ++ti) {
            if (pe.is64()) {
                const uint32_t t_rva = thunk_rva + static_cast<uint32_t>(ti * sizeof(uint64_t));
                const auto* t_raw = pe.at_rva(t_rva, sizeof(uint64_t));
                if (!t_raw) break;
                uint64_t thunk = 0; std::memcpy(&thunk, t_raw, sizeof(thunk));
                if (thunk == 0) break;
                ImportEntry e; e.dll = dll_lc;
                if (thunk & IMAGE_ORDINAL_FLAG64) {
                    e.by_ordinal = true;
                    e.function   = fmt::format("#{}", static_cast<uint16_t>(thunk & 0xFFFFu));
                } else {
                    const uint32_t name_rva = static_cast<uint32_t>(thunk & 0x7FFF'FFFFu);
                    // IMAGE_IMPORT_BY_NAME: {u16 Hint; char Name[];}
                    e.function = to_lower(pe.cstr_at_rva(name_rva + 2));
                }
                if (!e.function.empty()) out.push_back(std::move(e));
            } else {
                const uint32_t t_rva = thunk_rva + static_cast<uint32_t>(ti * sizeof(uint32_t));
                const auto* t_raw = pe.at_rva(t_rva, sizeof(uint32_t));
                if (!t_raw) break;
                uint32_t thunk = 0; std::memcpy(&thunk, t_raw, sizeof(thunk));
                if (thunk == 0) break;
                ImportEntry e; e.dll = dll_lc;
                if (thunk & IMAGE_ORDINAL_FLAG32) {
                    e.by_ordinal = true;
                    e.function   = fmt::format("#{}", static_cast<uint16_t>(thunk & 0xFFFFu));
                } else {
                    const uint32_t name_rva = thunk & 0x7FFF'FFFFu;
                    e.function = to_lower(pe.cstr_at_rva(name_rva + 2));
                }
                if (!e.function.empty()) out.push_back(std::move(e));
            }
        }
    }
    return out;
}

}  // namespace angelia::riskscore
