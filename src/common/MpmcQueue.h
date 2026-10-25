#pragma once

// Bounded MPMC queue (Vyukov). Wait-free push/pop under contention as long
// as the queue is not full/empty. Capacity must be a power of two. `T`
// must be trivially copyable — we store event indices (uint32_t) or POD
// record pointers, not owning types.

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

namespace angelia::common {

#if defined(__cpp_lib_hardware_interference_size)
inline constexpr std::size_t kCacheLine = std::hardware_destructive_interference_size;
#else
inline constexpr std::size_t kCacheLine = 64;
#endif

template <typename T>
class MpmcQueue {
    static_assert(std::is_trivially_copyable_v<T>,
        "MpmcQueue is for POD payloads (indices / pointers)");

    struct alignas(kCacheLine) Cell {
        std::atomic<std::size_t> sequence;
        T                        value;
    };

public:
    explicit MpmcQueue(std::size_t capacity)
        : mask_(capacity - 1),
          buffer_(static_cast<Cell*>(::operator new[](sizeof(Cell) * capacity, std::align_val_t{kCacheLine}))) {
        assert(capacity >= 2 && (capacity & (capacity - 1)) == 0 &&
               "MpmcQueue capacity must be a power of two");
        for (std::size_t i = 0; i < capacity; ++i) {
            new (&buffer_[i]) Cell{};
            buffer_[i].sequence.store(i, std::memory_order_relaxed);
        }
        enqueue_pos_.store(0, std::memory_order_relaxed);
        dequeue_pos_.store(0, std::memory_order_relaxed);
    }

    ~MpmcQueue() {
        const std::size_t cap = mask_ + 1;
        for (std::size_t i = 0; i < cap; ++i) buffer_[i].~Cell();
        ::operator delete[](buffer_, std::align_val_t{kCacheLine});
    }

    MpmcQueue(const MpmcQueue&)            = delete;
    MpmcQueue& operator=(const MpmcQueue&) = delete;

    bool try_push(const T& v) noexcept {
        Cell*        cell;
        std::size_t  pos = enqueue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &buffer_[pos & mask_];
            const std::size_t seq  = cell->sequence.load(std::memory_order_acquire);
            const intptr_t    diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);
            if (diff == 0) {
                if (enqueue_pos_.compare_exchange_weak(
                        pos, pos + 1, std::memory_order_relaxed)) break;
            } else if (diff < 0) {
                return false;  // full
            } else {
                pos = enqueue_pos_.load(std::memory_order_relaxed);
            }
        }
        cell->value = v;
        cell->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

    bool try_pop(T& out) noexcept {
        Cell*        cell;
        std::size_t  pos = dequeue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            cell = &buffer_[pos & mask_];
            const std::size_t seq  = cell->sequence.load(std::memory_order_acquire);
            const intptr_t    diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
            if (diff == 0) {
                if (dequeue_pos_.compare_exchange_weak(
                        pos, pos + 1, std::memory_order_relaxed)) break;
            } else if (diff < 0) {
                return false;  // empty
            } else {
                pos = dequeue_pos_.load(std::memory_order_relaxed);
            }
        }
        out = cell->value;
        cell->sequence.store(pos + mask_ + 1, std::memory_order_release);
        return true;
    }

    // Approximate size; snapshotted, not synchronised.
    std::size_t size_approx() const noexcept {
        const auto e = enqueue_pos_.load(std::memory_order_relaxed);
        const auto d = dequeue_pos_.load(std::memory_order_relaxed);
        return e >= d ? (e - d) : 0;
    }

    std::size_t capacity() const noexcept { return mask_ + 1; }

private:
    const std::size_t                   mask_;
    Cell*                               buffer_;
    alignas(kCacheLine) std::atomic<std::size_t> enqueue_pos_{0};
    alignas(kCacheLine) std::atomic<std::size_t> dequeue_pos_{0};
};

}  // namespace angelia::common
