#pragma once

// KrabsETW-backed producer. Subscribes to a kernel real-time session and
// pushes fully-materialised EventRecord slots into the writer's queue.
//
// Requires Administrator (SeSecurityPrivilege / EVENT_TRACE_SYSTEM_LOGGER_MODE).
// The tools/p01_kernel_smoke harness elevation-guards for you.

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "collector/SqliteWriter.h"

namespace angelia::collector {

class KrabsConsumer {
public:
    explicit KrabsConsumer(SqliteWriter& writer);
    ~KrabsConsumer();

    KrabsConsumer(const KrabsConsumer&)            = delete;
    KrabsConsumer& operator=(const KrabsConsumer&) = delete;

    // Which kernel providers to subscribe to. Enable-time bugs on newer
    // Windows builds (26100+) sometimes reject a particular combination
    // with ERROR_INVALID_PARAMETER — bisecting via this bitmask lets an
    // operator narrow it down without editing code.
    struct Providers {
        bool process    = true;
        bool image_load = true;
        bool file_io    = true;
        bool registry   = true;
    };

    // Runs the kernel session on a dedicated thread. Throws std::runtime_error
    // if the session cannot be started (usually: not elevated).
    void start(const std::string& session_name = "angelia-p01",
               const Providers&   providers    = {});
    void stop();

    struct LossStats {
        bool available = false;
        uint32_t events_lost = 0;
        uint32_t log_buffers_lost = 0;
        uint32_t realtime_buffers_lost = 0;
    };
    LossStats query_loss_stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    SqliteWriter&         writer_;
    std::thread           thread_;
    std::atomic<bool>     running_{false};
};

}  // namespace angelia::collector
