#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include "riskscore/Entropy.h"

using angelia::riskscore::shannon_entropy;

TEST(Entropy, AllZeroBufferIsZero) {
    std::vector<uint8_t> buf(4096, 0);
    EXPECT_DOUBLE_EQ(shannon_entropy(buf.data(), buf.size()), 0.0);
}

TEST(Entropy, UniformRandomIsCloseToEight) {
    std::mt19937 rng(0xC0FFEEu);
    std::vector<uint8_t> buf(64 * 1024);
    for (auto& b : buf) b = static_cast<uint8_t>(rng() & 0xFF);
    const double h = shannon_entropy(buf.data(), buf.size());
    EXPECT_GT(h, 7.9);
    EXPECT_LT(h, 8.001);
}

TEST(Entropy, TwoValuesGivesOneBit) {
    std::vector<uint8_t> buf(1000, 0);
    for (std::size_t i = 0; i < buf.size() / 2; ++i) buf[i] = 1;
    EXPECT_NEAR(shannon_entropy(buf.data(), buf.size()), 1.0, 1e-9);
}

TEST(Entropy, EmptyBufferIsZero) {
    EXPECT_DOUBLE_EQ(shannon_entropy(nullptr, 0), 0.0);
}
