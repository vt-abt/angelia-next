#include "common/Logging.h"

#include <spdlog/sinks/stdout_color_sinks.h>

#include <memory>

namespace angelia::common {

void init_logging(spdlog::level::level_enum lvl) {
    static bool initialised = false;
    if (initialised) {
        spdlog::set_level(lvl);
        return;
    }
    auto logger = spdlog::stderr_color_mt("angelia");
    logger->set_pattern("%H:%M:%S.%e [%^%l%$] %v");
    logger->set_level(lvl);
    spdlog::set_default_logger(std::move(logger));
    spdlog::set_level(lvl);
    initialised = true;
}

}
