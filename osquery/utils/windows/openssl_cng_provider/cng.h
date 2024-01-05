#pragma once

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
class OpenSSLCNGContext {
 public:
  OpenSSLCNGContext();

 private:
  OSSL_LIB_CTX* lib_ctx;
  OSSL_PROVIDER* default_provider;
  OSSL_PROVIDER* cng_provider;
};
} // namespace osquery
