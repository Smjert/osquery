/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/resources.h>

#include <libproc.h>

namespace osquery {
Expected<std::uint64_t, ResourceError> getProcessMemoryFootprint(
    const std::uint32_t process_id) {
  using ProcExpected = Expected<std::uint64_t, ResourceError>;

  struct rusage_info_v1 rusage_info_data;
  int status = proc_pid_rusage(
      process_id, RUSAGE_INFO_V1, (rusage_info_t*)&rusage_info_data);

  if (status < 0) {
    return ProcExpected::failure("Failed to get memory usage");
  }

  return rusage_info_data.ri_phys_footprint;
}
} // namespace osquery
