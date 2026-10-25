#pragma once

// One-line spdlog setup so every tool logs the same way. Call
// init_logging() once at start of main().

#include <spdlog/spdlog.h>

namespace angelia::common {

void init_logging(spdlog::level::level_enum lvl = spdlog::level::info);

}
