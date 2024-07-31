/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <optional>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

extern "C" {
/* Function called by OpenSSL to initialize the provider.
   Pass it to the OSSL_PROVIDER_add_builtin function. */
int OsqueryCNGProviderInit(const OSSL_CORE_HANDLE* handle,
                           const OSSL_DISPATCH* in,
                           const OSSL_DISPATCH** out,
                           void** prov_ctx);
}

namespace osquery {
// class OpenSSLCNGProviderContext {
//  public:
//   OpenSSLCNGProviderContext(OSSL_LIB_CTX& lib_ctx,
//                             OSSL_PROVIDER& default_provider,
//                             OSSL_PROVIDER& cng_provider);

//   OSSL_LIB_CTX& getLibraryContext() {
//     return *lib_ctx_;
//   }

//  private:
//   OSSL_LIB_CTX* lib_ctx_;
//   OSSL_PROVIDER* default_provider_;
//   OSSL_PROVIDER* cng_provider_;
// };

// std::optional<OpenSSLCNGProviderContext> InitializeOpenSSLCNGProvider();
} // namespace osquery
