#include <osquery/utils/system/resources.h>

// Keep above Windows system headers
#include <osquery/utils/system/windows/system.h>

#include <psapi.h>

namespace osquery {

Expected<std::uint64_t, ResourceError> getProcessTotalMemoryUsage(
    const std::uint32_t process_id) {
  using ProcExpected = Expected<std::uint64_t, ResourceError>;

  auto proc_handle =
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);

  if (proc_handle == nullptr) {
    return ProcExpected::failure("Failed to get process handle of pid " +
                                 std::to_string(process_id));
  }

  PROCESS_MEMORY_COUNTERS_EX mem_ctr;
  auto ret =
      GetProcessMemoryInfo(proc_handle,
                           reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&mem_ctr),
                           sizeof(PROCESS_MEMORY_COUNTERS_EX));

  if (ret != TRUE) {
    return ProcExpected::failure(
        "Could not retrieve memory information of pid " +
        std::to_string(process_id));
  }

  return mem_ctr.PrivateUsage;
}
} // namespace osquery
