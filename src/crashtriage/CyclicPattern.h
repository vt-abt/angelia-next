#pragma once

// Metasploit-style cyclic pattern ("Aa0Aa1Aa2...Ab0Ab1..."). Each 4-byte
// window is unique up to ~20 KiB — enough to pinpoint the offset in the
// input at which a specific register or stack slot was overwritten.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace angelia::crashtriage {

inline constexpr std::size_t kCyclicMaxLength = 26 * 26 * 10 * 3;   // 20280

// Generate `length` bytes of the cyclic pattern; capped at kCyclicMaxLength.
std::string generate_pattern(std::size_t length);

// Find the offset of the first occurrence of a 4-byte little-endian
// value in the cyclic pattern (searching up to kCyclicMaxLength).
// Returns nullopt when not present.
std::optional<std::size_t> find_offset(uint32_t four_bytes_le);

// Same, but for an arbitrary byte sequence (usually 4-8 bytes read from
// a register). Little-endian is the natural interpretation for x64.
std::optional<std::size_t> find_offset(std::string_view needle);

}  // namespace angelia::crashtriage
