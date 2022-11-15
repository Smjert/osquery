#include "memory.h"

#include <future>
#include <string>

#include <osquery/logger/logger.h>

namespace osquery {

namespace {

void memoryProfilingThread(std::condition_variable& memory_thread_cond,
                           std::mutex& memory_thread_mutex,
                           bool& memory_thread_has_started,
                           std::promise<std::uint64_t> peak_memory_promise,
                           std::future<void> should_stop) {
  {
    std::unique_lock lock(memory_thread_mutex);
    memory_thread_cond.notify_one();
  }

  std::uint64_t peak_memory = 0;

  do {
    auto memory_expected = osquery::getProcessTotalMemoryUsage(getpid());

    std::uint64_t memory = 0;
    if (memory_expected.isError()) {
      VLOG(1) << memory_expected.getError().getMessage();
    } else {
      memory = memory_expected.take();
    }

    if (memory > peak_memory) {
      peak_memory = memory;
    }
  } while (should_stop.wait_for(std::chrono::milliseconds(500)) ==
           std::future_status::timeout);

  // If the loop above has never run, ensure that we get at least one read
  if (peak_memory == 0) {
    peak_memory = osquery::getProcessTotalMemoryUsage(getpid()).takeOr(
        static_cast<std::uint64_t>(0));
  }

  peak_memory_promise.set_value(peak_memory);
}

} // namespace

MemoryPeakProfiler::MemoryPeakProfiler(std::uint64_t interval_ms)
    : interval_ms_(interval_ms) {
  std::promise<std::uint64_t> memory_peak_promise_;
  memory_peak_ = memory_peak_promise_.get_future();

  std::thread(memoryProfilingThread,
              memory_thread_cond_,
              memory_thread_mutex_,
              std::move(memory_peak_promise_),
              stop_thread_promise_.get_future())
      .detach();

  {
    /* We want to wait until the thread starts,
       so that we know we are monitoring the memory */
    std::unique_lock lock(memory_thread_mutex_);
    memory_thread_cond.wait(lock, [] { return memory_thread_has_started_; });
  }
}

std::uint64_t MemoryPeakProfiler::getMemoryPeak() {
  stop_thread.set_value();

  return memory_peak_.get();
}

MemoryPeakProfiler::~MemoryPeakProfiler() {
  stop_thread.set_value();

  memory_peak_.wait();
}

} // namespace osquery
