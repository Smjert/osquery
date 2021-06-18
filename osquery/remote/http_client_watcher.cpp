/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "http_client_watcher.h"

#include <algorithm>
#include <iostream>
#include <thread>

#include <osquery/core/shutdown.h>

namespace osquery::http {

void HTTPClientWatcher::ShutdownListener::run() {
  waitForShutdown();
  std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
  HTTPClientWatcher::instance()->interrupt();
  std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
}

HTTPClientWatcher::HTTPClientWatcher(PrivateConstructorTag)
    : InternalRunnable("HTTPClientWatcher") {}

std::shared_ptr<HTTPClientWatcher>& HTTPClientWatcher::instance() {
  static auto watcher =
      std::make_shared<HTTPClientWatcher>(PrivateConstructorTag{});

  return watcher;
}

void HTTPClientWatcher::watchClient(
    std::weak_ptr<InterruptibleRunnable> client) {
  if (interrupted()) {
    return;
  }

  context.clients_to_watch.push_back(client);
}

void HTTPClientWatcher::start() {
  while (!interrupted()) {
    std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
    pause(std::chrono::milliseconds(5000));
    std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;

    cleanDeadClients();
    std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
  }

  std::unique_lock<std::mutex> lock(context.context_mutex);
  std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
  interruptClients();
  std::cout << __func__ << "(" << __LINE__ << ")" << std::endl;
}

void HTTPClientWatcher::stop() {}

void HTTPClientWatcher::cleanDeadClients() {
  std::unique_lock<std::mutex> lock(context.context_mutex);

  std::cout << "Cleaning dead clients" << std::endl;

  context.clients_to_watch.erase(
      std::remove_if(context.clients_to_watch.begin(),
                     context.clients_to_watch.end(),
                     [](auto client) { return client.expired(); }),
      context.clients_to_watch.end());
}

void HTTPClientWatcher::interruptClients() {
  std::cout << "Interrupting clients" << std::endl;

  for (const auto& client : context.clients_to_watch) {
    auto pinned_client = client.lock();
    if (pinned_client == nullptr) {
      continue;
    }

    std::cout << "Interrupting one client" << std::endl;

    pinned_client->interrupt();
  }
}
} // namespace osquery::http
