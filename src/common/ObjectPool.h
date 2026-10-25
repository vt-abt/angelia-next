#pragma once

// Fixed-capacity, lock-free object pool. Preallocated slots plus an
// MPMC index queue as the free-list. `try_acquire()` returns nullptr when
// exhausted — the collector treats that as a drop and increments its
// counter rather than blocking the ETW callback.

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <thread>
#include <type_traits>
#include <vector>

#include "common/MpmcQueue.h"

namespace angelia::common {

template <typename T>
class ObjectPool {
public:
    static_assert(std::is_trivially_destructible_v<T>,
        "pool records must be trivially destructible (they are POD event rows)");

    explicit ObjectPool(std::size_t capacity)
        : slots_(capacity),
          free_(round_up_pow2(capacity)) {
        for (std::size_t i = 0; i < capacity; ++i) {
            const bool ok = free_.try_push(static_cast<uint32_t>(i));
            assert(ok && "queue capacity must be >= pool capacity");
            (void)ok;
        }
    }

    ObjectPool(const ObjectPool&)            = delete;
    ObjectPool& operator=(const ObjectPool&) = delete;

    // Returns a zeroed record from the pool, or nullptr if exhausted.
    T* try_acquire() noexcept {
        uint32_t idx;
        if (!free_.try_pop(idx)) return nullptr;
        T* p = &slots_[idx];
        std::memset(static_cast<void*>(p), 0, sizeof(T));
        return p;
    }

    void release(T* p) noexcept {
        assert(p >= slots_.data() && p < slots_.data() + slots_.size());
        const auto idx = static_cast<uint32_t>(p - slots_.data());
        // The free-list must never leak: Vyukov's bounded MPMC can
        // transiently report "full" under contention (a concurrent
        // pop's sequence store hasn't propagated yet), so retry until
        // the slot is safely back on the list. The queue capacity is
        // >= pool capacity, so this terminates.
        while (!free_.try_push(idx)) {
            std::this_thread::yield();
        }
    }

    std::size_t capacity() const noexcept { return slots_.size(); }
    std::size_t free_slots_approx() const noexcept { return free_.size_approx(); }

private:
    static std::size_t round_up_pow2(std::size_t n) noexcept {
        std::size_t p = 1;
        while (p < n) p <<= 1;
        return p;
    }

    std::vector<T>       slots_;
    MpmcQueue<uint32_t>  free_;
};

}  // namespace angelia::common
