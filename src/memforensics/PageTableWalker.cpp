#include "memforensics/PageTableWalker.h"

#include "memforensics/PhysicalMemoryReader.h"

#include <cstring>

namespace angelia::memforensics {

namespace {

inline constexpr uint64_t kPresent = 1ull << 0;
inline constexpr uint64_t kPS      = 1ull << 7;   // large-page bit at PDPTE/PDE

// Bits [12..51] of the entry hold the next-level table's physical page
// number. Mask off flags below 12 and the reserved / NX bits above 51.
inline constexpr uint64_t kAddrMask = 0x000F'FFFF'FFFF'F000ull;

inline uint64_t read_entry(PhysicalMemoryReader& phys, uint64_t table_phys, unsigned idx) {
    const uint64_t entry_pa = table_phys | (static_cast<uint64_t>(idx) << 3);
    auto v = phys.read_pod<uint64_t>(entry_pa);
    return v.value_or(0);
}

inline unsigned idx9(uint64_t va, unsigned shift) {
    return static_cast<unsigned>((va >> shift) & 0x1FFu);
}

}  // namespace

std::optional<uint64_t> PageTableWalker::translate(uint64_t va) const noexcept {
    const uint64_t pml4e = read_entry(phys_, cr3_, idx9(va, 39));
    if (!(pml4e & kPresent)) return std::nullopt;

    const uint64_t pdpt = pml4e & kAddrMask;
    const uint64_t pdpte = read_entry(phys_, pdpt, idx9(va, 30));
    if (!(pdpte & kPresent)) return std::nullopt;
    if (pdpte & kPS) {
        // 1 GiB page: physical = (pdpte & 1G-page-mask) | (va & 0x3FFF_FFFF)
        return (pdpte & 0x000F'FFFFC000'0000ull) | (va & 0x3FFF'FFFFull);
    }

    const uint64_t pd = pdpte & kAddrMask;
    const uint64_t pde = read_entry(phys_, pd, idx9(va, 21));
    if (!(pde & kPresent)) return std::nullopt;
    if (pde & kPS) {
        // 2 MiB page: physical = (pde & 2M-page-mask) | (va & 0x1FFFFF)
        return (pde & 0x000F'FFFF'FFE0'0000ull) | (va & 0x001F'FFFFull);
    }

    const uint64_t pt = pde & kAddrMask;
    const uint64_t pte = read_entry(phys_, pt, idx9(va, 12));
    if (!(pte & kPresent)) return std::nullopt;
    return (pte & kAddrMask) | (va & 0xFFFull);
}

std::size_t PageTableWalker::read_virtual(uint64_t va, void* out, std::size_t n) const noexcept {
    std::size_t total = 0;
    auto* dst = static_cast<uint8_t*>(out);
    while (n > 0) {
        auto pa = translate(va);
        if (!pa) return total;
        // Never straddle a page boundary in one physical read; the next
        // page may map somewhere completely different.
        const std::size_t in_page = static_cast<std::size_t>(0x1000 - (va & 0xFFF));
        const std::size_t take    = std::min(n, in_page);
        const std::size_t got     = phys_.read(*pa, dst, take);
        total += got;
        if (got < take) return total;
        va  += take;
        dst += take;
        n   -= take;
    }
    return total;
}

}  // namespace angelia::memforensics
