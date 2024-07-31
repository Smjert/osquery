/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

namespace osquery {
constexpr const char* algorithm_properties =
    "provider=keychain_provider,fips=0";

using OSSLKeychainFunctionPtr = void (*)();
} // namespace osquery
