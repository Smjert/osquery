#pragma once

#include <atomic>
#include <memory>
#include <optional>
#include <string>

#include <boost/core/noncopyable.hpp>

#include <osquery/utils/info/tool_type.h>
#include <osquery/utils/openssl/openssl_utils.h>

namespace osquery {
class Initializer : private boost::noncopyable {
 public:
  /**
   * @brief Sets up various aspects of osquery execution state.
   *
   * osquery needs a few things to happen as soon as the process begins
   * executing. Initializer takes care of setting up the relevant parameters.
   * Initializer should be called in an executable's `main()` function.
   *
   * @param argc the number of elements in argv
   * @param argv the command-line arguments passed to `main()`
   * @param tool the type of osquery main (daemon, shell, test, extension).
   * @param init_glog whether to start google logging module (it can be
   * initialized at most once)
   */
  Initializer(int& argc,
              char**& argv,
              ToolType tool = ToolType::TEST,
              bool init_glog = true);

  ~Initializer();

  /**
   * @brief Sets up the process as an osquery daemon.
   *
   * A daemon has additional constraints, it can use a process mutex, check
   * for sane/non-default configurations, etc.
   */
  void initDaemon() const;

  /**
   * @brief Sets up the process as an osquery shell.
   *
   * The shell is lighter than a daemon and disables (by default) features.
   */
  void initShell() const;

  /**
   * @brief Daemon tools may want to continually spawn worker processes
   * and monitor their utilization.
   *
   * A daemon may call initWorkerWatcher to begin watching child daemon
   * processes until it-itself is unscheduled. The basic guarantee is that only
   * workers will return from the function.
   *
   * The worker-watcher will implement performance bounds on CPU utilization
   * and memory, as well as check for zombie/defunct workers and respawn them
   * if appropriate. The appropriateness is determined from heuristics around
   * how the worker exited. Various exit states and velocities may cause the
   * watcher to resign.
   *
   * @param name The name of the worker process.
   */
  void initWorkerWatcher(const std::string& name = "") const;

  /// Assume initialization finished, start work.
  void start() const;

  /**
   * @brief Cleanly shutdown all services and components.
   *
   * Issue interrupt/stop requests to all service threads, join them, then
   * stop the eventing system, database usage, and run any platform-specific
   * teardown logic.
   *
   * If a request to shutdown stored a non-0 return code, that will override
   * the input return code if the input is 0. If the caller assumes success
   * and something else indicated failure we return with the failure code.
   *
   * If the main thread is out of actions it can call #shutdown.
   *
   * @param retcode Caller (main thread's) request return code.
   * @return The most appropriate return code.
   */
  int shutdown(int retcode) const;

  /// For compatibility. See the global method waitForShutdown.
  void waitForShutdown() const;

  /// For compatibility. See the global method requestShutdown.
  static void requestShutdown(int retcode = EXIT_SUCCESS);

  /// For compatibility. See the global method requestShutdown.
  static void requestShutdown(int retcode, const std::string& system_log);

  /// Exit immediately without requesting the dispatcher to stop.
  static void shutdownNow(int retcode = EXIT_SUCCESS);

  /**
   * @brief Check if a process is an osquery worker.
   *
   * By default an osqueryd process will fork/exec then set an environment
   * variable: `OSQUERY_WORKER` while continually monitoring child I/O.
   * The environment variable causes subsequent child processes to skip several
   * initialization steps and jump into extension handling, registry setup,
   * config/logger discovery and then the event publisher and scheduler.
   */
  static bool isWorker();

  /**
   * @brief Check is a process is an osquery watcher.
   *
   * Is watcher is different from the opposite of isWorker. An osquery process
   * may have disabled the watchdog so the parent could be doing the work or
   * the worker child.
   */
  static bool isWatcher();

  /// Initialize this process as an osquery daemon worker.
  void initWorker(const std::string& name) const;

  /// Initialize the osquery watcher, optionally spawn a worker.
  void initWatcher() const;

  /// This pauses the watchdog process until the watcher thread stops.
  void waitForWatcher() const;

  static void resourceLimitHit();
  static bool isResourceLimitHit();

  /// Gets the OpenSSL library context necessary for custom providers to create
  /// new OpenSSL contexts
  static OpenSSLProviderContext& getOpenSSLCustomProviderContext();

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// Set and wait for an active plugin optionally broadcasted.
  void initActivePlugin(const std::string& type, const std::string& name) const;

  /// A saved, mutable, reference to the process's argc.
  int* argc_{nullptr};

  /// A saved, mutable, reference to the process's argv.
  char*** argv_{nullptr};

  /// The deduced program name determined by executing path.
  std::string binary_;

  /// Is this a worker process
  static bool isWorker_;

  static std::atomic<bool> resource_limit_hit_;

  static std::optional<OpenSSLProviderContext> openssl_custom_provider_context_;
};
} // namespace osquery
