#pragma once

#include <osquery/utils/openssl/openssl_context.h>

namespace osquery {
class GlobalOpenSSLProviderContext {
 public:
  static OpenSSLProviderContext& getContext() {
    return context;
  }
  static O

 private:
  static OpenSSLProviderContext context;
}

} // namespace osquery
