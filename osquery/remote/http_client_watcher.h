/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <thread>
#include <vector>

#include <osquery/dispatcher/dispatcher.h>

namespace osquery::http {

class HTTPClientWatcher final : public InternalRunnable {
  struct PrivateConstructorTag {};

 public:
  class ShutdownListener {
   public:
    static void run();
  };

  static std::shared_ptr<HTTPClientWatcher>& instance();

  HTTPClientWatcher(PrivateConstructorTag);

  void watchClient(std::weak_ptr<InterruptibleRunnable> client);

 private:
  void start() override;
  void interruptClients();
  void cleanDeadClients();
  struct ThreadContext {
    std::vector<std::weak_ptr<InterruptibleRunnable>> clients_to_watch;
    std::mutex context_mutex;
  };

  void stop() override;

  ThreadContext context;
};
} // namespace osquery::http
