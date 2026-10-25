#include "riskscore/Entropy.h"

#include <array>
#include <cmath>

namespace angelia::riskscore {

double shannon_entropy(const void* data, std::size_t n) noexcept {
    if (n == 0 || !data) return 0.0;
    std::array<uint32_t, 256> hist{};
    const auto* p = static_cast<const uint8_t*>(data);
    for (std::size_t i = 0; i < n; ++i) ++hist[p[i]];
    double h = 0.0;
    const double inv = 1.0 / static_cast<double>(n);
    for (uint32_t c : hist) {
        if (c == 0) continue;
        const double pi = static_cast<double>(c) * inv;
        h -= pi * std::log2(pi);
    }
    return h;
}

}  // namespace angelia::riskscore
