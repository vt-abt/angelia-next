#include "crashtriage/CyclicPattern.h"

#include <algorithm>

namespace angelia::crashtriage {

namespace {

constexpr char kUpper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr char kLower[] = "abcdefghijklmnopqrstuvwxyz";
constexpr char kDigit[] = "0123456789";

std::string full_pattern() {
    std::string p;
    p.reserve(kCyclicMaxLength);
    for (char u : std::string_view(kUpper, 26)) {
        for (char l : std::string_view(kLower, 26)) {
            for (char d : std::string_view(kDigit, 10)) {
                p.push_back(u);
                p.push_back(l);
                p.push_back(d);
            }
        }
    }
    return p;
}

const std::string& cached_full() {
    static const std::string p = full_pattern();
    return p;
}

}  // namespace

std::string generate_pattern(std::size_t length) {
    const auto& full = cached_full();
    return full.substr(0, std::min(length, full.size()));
}

std::optional<std::size_t> find_offset(std::string_view needle) {
    if (needle.empty()) return std::nullopt;
    const auto& full = cached_full();
    const auto pos = full.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    return pos;
}

std::optional<std::size_t> find_offset(uint32_t four_bytes_le) {
    char bytes[4];
    bytes[0] = static_cast<char>((four_bytes_le      ) & 0xff);
    bytes[1] = static_cast<char>((four_bytes_le >>  8) & 0xff);
    bytes[2] = static_cast<char>((four_bytes_le >> 16) & 0xff);
    bytes[3] = static_cast<char>((four_bytes_le >> 24) & 0xff);
    return find_offset(std::string_view(bytes, 4));
}

}  // namespace angelia::crashtriage
