#pragma once

// x64 4-level page-table walker (PML4 → PDPT → PD → PT → physical page).
// Reads each table entry through a PhysicalMemoryReader; returns the
// physical address a virtual address translates to, or nullopt when any
// level fails the Present check. Handles 1 GiB pages (PS bit at PDPTE)
// and 2 MiB pages (PS bit at PDE) — anything else is a 4 KiB translation.

#include <cstdint>
#include <optional>

namespace angelia::memforensics {

class PhysicalMemoryReader;

class PageTableWalker {
public:
    // `cr3` must be the physical address of the process' PML4 table.
    // The low 12 bits (PCID / flags) are stripped on entry.
    explicit PageTableWalker(PhysicalMemoryReader& phys, uint64_t cr3) noexcept
        : phys_(phys), cr3_(cr3 & ~static_cast<uint64_t>(0xFFF)) {}

    std::optional<uint64_t> translate(uint64_t va) const noexcept;

    // Helper: read `n` bytes at virtual address `va` into `out`, walking
    // one page at a time. Returns bytes actually copied.
    std::size_t read_virtual(uint64_t va, void* out, std::size_t n) const noexcept;

    template <typename T>
    std::optional<T> read_virtual_pod(uint64_t va) const noexcept {
        static_assert(std::is_trivially_copyable_v<T>);
        T v{};
        if (read_virtual(va, &v, sizeof(T)) != sizeof(T)) return std::nullopt;
        return v;
    }

    uint64_t cr3() const noexcept { return cr3_; }

private:
    PhysicalMemoryReader& phys_;
    uint64_t              cr3_;
};

}  // namespace angelia::memforensics
