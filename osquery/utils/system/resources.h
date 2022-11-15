#pragma once

#include <cstdint>

#include <osquery/utils/expected/expected.h>

namespace osquery {
enum class ResourceError { GenericError };

Expected<std::uint64_t, ResourceError> getProcessTotalMemoryUsage(
    const std::uint32_t process_id);
} // namespace osquery
