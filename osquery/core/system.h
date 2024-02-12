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
#include <string>

namespace osquery {

class Status;

/**
 * @brief Generate a new generic UUID
 *
 * @return a string containing a random UUID
 */
std::string generateNewUUID();

/**
 * @brief Getter for an instance uuid
 *
 * @return ok on success and ident is set to the instance uuid, otherwise
 * failure.
 */
Status getInstanceUUID(std::string& ident);

/**
 * @brief Getter for an ephemeral uuid
 *
 * @return ok on success and ident is set to the ephemeral uuid, otherwise
 * failure.
 */
Status getEphemeralUUID(std::string& ident);

/**
 * @brief Getter for a host's uuid.
 *
 * @return ok on success and ident is set to the host's uuid, otherwise failure.
 */
Status getHostUUID(std::string& ident);

/**
 * @brief Determine whether the UUID is a placeholder.
 *
 * Some motherboards report placeholder UUIDs which, from point of view of being
 * unique, are useless. This method checks the provided UUID against a list of
 * known placeholders so that it can be treated as invalid. This method ignores
 * case.
 *
 * @param uuid UUID to test.
 * @return true if UUID is a placeholder and false otherwise.
 */
bool isPlaceholderHardwareUUID(const std::string& uuid);

/**
 * @brief generate a uuid to uniquely identify this machine
 *
 * @return uuid string to identify this machine
 */
std::string generateHostUUID();

/**
 * @brief Get a configured UUID/name that uniquely identify this machine
 *
 * @return string to identify this machine
 */
std::string getHostIdentifier();

/**
 * @brief Getter for determining Admin status
 *
 * @return A bool indicating if the current process is running as admin
 */
bool isUserAdmin();

/**
 * @brief Set the name of the thread
 *
 * @return If the name was set successfully
 */
Status setThreadName(const std::string& name);

/// Get the osquery tool start time.
uint64_t getStartTime();

/// Set the osquery tool start time.
void setStartTime(uint64_t st);

/**
 * @brief Initialize any platform dependent libraries or objects.
 *
 * On windows, we require the COM libraries be initialized just once.
 */
void platformSetup();

/**
 * @brief Before ending, tear down any platform specific setup.
 *
 * On windows, we require the COM libraries be initialized just once.
 */
void platformTeardown();

bool checkPlatform(const std::string& platform);
} // namespace osquery
