/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <vector>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

extern "C" {

int OsqueryKeychainProviderInit(const OSSL_CORE_HANDLE* handle,
                                const OSSL_DISPATCH* in,
                                const OSSL_DISPATCH** out,
                                void** prov_ctx);
}
