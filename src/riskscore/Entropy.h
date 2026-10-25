#pragma once

// Shannon entropy over a byte buffer. Result in [0.0, 8.0]. High-entropy
// sections (> ~7.0) inside an executable are a packer/encryption
// indicator; ordinary compiled code sits in the 5.5–6.5 band.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace angelia::riskscore {

double shannon_entropy(const void* data, std::size_t n) noexcept;

inline double shannon_entropy(std::string_view sv) noexcept {
    return shannon_entropy(sv.data(), sv.size());
}

}  // namespace angelia::riskscore
