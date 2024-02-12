#pragma once

#include <vector>

#include <openssl/params.h>

namespace osquery {
struct CNGProviderCtx {
  const OSSL_DISPATCH* core_functions;
};
} // namespace osquery
