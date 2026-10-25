#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "common/ObjectPool.h"

namespace {

struct Row {
    uint64_t a = 0;
    uint64_t b = 0;
};

TEST(ObjectPool, AcquireReleaseSingleThreaded) {
    angelia::common::ObjectPool<Row> pool(8);
    std::vector<Row*> acquired;
    for (int i = 0; i < 8; ++i) {
        Row* r = pool.try_acquire();
        ASSERT_NE(r, nullptr);
        r->a = static_cast<uint64_t>(i);
        acquired.push_back(r);
    }
    EXPECT_EQ(pool.try_acquire(), nullptr);
    for (auto* r : acquired) pool.release(r);
    Row* r = pool.try_acquire();
    ASSERT_NE(r, nullptr);
    // Records are zeroed on acquire.
    EXPECT_EQ(r->a, 0u);
    EXPECT_EQ(r->b, 0u);
    pool.release(r);
}

TEST(ObjectPool, ContendedAcquireRelease) {
    constexpr std::size_t kCap = 4096;
    angelia::common::ObjectPool<Row> pool(kCap);
    std::atomic<uint64_t> ok{0}, fail{0};
    constexpr int kThreads = 8;
    constexpr int kOps     = 20'000;
    std::vector<std::thread> ts;
    for (int t = 0; t < kThreads; ++t) {
        ts.emplace_back([&] {
            for (int i = 0; i < kOps; ++i) {
                Row* r = pool.try_acquire();
                if (!r) { fail.fetch_add(1); continue; }
                r->a = 1; r->b = 2;
                pool.release(r);
                ok.fetch_add(1);
            }
        });
    }
    for (auto& t : ts) t.join();
    EXPECT_EQ(ok.load() + fail.load(), static_cast<uint64_t>(kThreads * kOps));
    EXPECT_EQ(pool.free_slots_approx(), kCap);
}

}  // namespace
