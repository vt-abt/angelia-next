#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "common/MpmcQueue.h"

namespace {

TEST(MpmcQueue, BoundedPushPop) {
    angelia::common::MpmcQueue<uint32_t> q(4);
    for (uint32_t i = 0; i < 4; ++i) EXPECT_TRUE(q.try_push(i));
    EXPECT_FALSE(q.try_push(99));
    uint32_t v = 0;
    for (uint32_t i = 0; i < 4; ++i) {
        ASSERT_TRUE(q.try_pop(v));
        EXPECT_EQ(v, i);
    }
    EXPECT_FALSE(q.try_pop(v));
}

TEST(MpmcQueue, MpMcConservation) {
    constexpr std::size_t kCap = 1 << 14;
    angelia::common::MpmcQueue<uint64_t> q(kCap);
    constexpr int kProducers = 4;
    constexpr int kConsumers = 4;
    constexpr uint64_t kPer  = 100'000;

    std::atomic<uint64_t> pushed_sum{0};
    std::atomic<uint64_t> popped_sum{0};
    std::atomic<uint64_t> popped_count{0};
    std::atomic<bool> producers_done{false};

    std::vector<std::thread> ps, cs;
    for (int t = 0; t < kProducers; ++t) {
        ps.emplace_back([&, t] {
            const uint64_t base = uint64_t(t) * kPer + 1;
            for (uint64_t i = 0; i < kPer; ++i) {
                const uint64_t v = base + i;
                while (!q.try_push(v)) std::this_thread::yield();
                pushed_sum.fetch_add(v, std::memory_order_relaxed);
            }
        });
    }
    for (int c = 0; c < kConsumers; ++c) {
        cs.emplace_back([&] {
            uint64_t v = 0;
            while (!producers_done.load(std::memory_order_acquire) ||
                   q.size_approx() > 0) {
                if (q.try_pop(v)) {
                    popped_sum.fetch_add(v, std::memory_order_relaxed);
                    popped_count.fetch_add(1, std::memory_order_relaxed);
                } else {
                    std::this_thread::yield();
                }
            }
        });
    }
    for (auto& t : ps) t.join();
    producers_done.store(true, std::memory_order_release);
    for (auto& t : cs) t.join();

    EXPECT_EQ(popped_count.load(), uint64_t(kProducers) * kPer);
    EXPECT_EQ(popped_sum.load(),   pushed_sum.load());
}

}  // namespace
