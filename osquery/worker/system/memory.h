/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <condition_variable>
#include <cstdint>
#include <future>
#include <mutex>
#include <thread>

namespace osquery {

class MemoryPeakProfiler {
 public:
  MemoryPeakProfiler() = delete;
  MemoryPeakProfiler(std::uint64_t interval_ms);

  ~MemoryPeakProfiler();

  std::uint64_t getMemoryPeak();

 private:
  std::uint64_t interval_ms_;
  bool memory_thread_has_started_;
  std::mutex memory_thread_mutex_;
  std::condition_variable memory_thread_cond_;
  std::future<std::uint64_t> memory_peak_;
  std::promise<void> stop_thread_promise_;
};

#ifdef OSQUERY_LINUX
/* Attempts to release retained memory if the memory usage
   of the current process goes above a certain threshold. */
void releaseRetainedMemory();
#endif
} // namespace osquery
