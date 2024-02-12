#include "cng.h"

#include <iostream>

#include <openssl/provider.h>

#include <osquery/utils/openssl/windows/cng_provider/common/defines.h>
#include <osquery/utils/openssl/windows/cng_provider/common/provider_context.h>
#include <osquery/utils/openssl/windows/cng_provider/keymanagement/key_management.h>
#include <osquery/utils/openssl/windows/cng_provider/signature/signature.h>
#include <osquery/utils/openssl/windows/cng_provider/store/store.h>

namespace osquery {
constexpr char* provider_name = "CNG Provider";
constexpr char* provider_version = "0.0.1";
constexpr char* provider_buildinfo = "0.0.1";

static const OSSL_PARAM cng_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nullptr, 0),
    OSSL_PARAM_END};
} // namespace osquery

extern "C" {
static int OsqueryCNGProviderIsRunning() {
  return 1;
}

static const OSSL_PARAM* OsqueryCNGGetTableParams(
    [[maybe_unused]] void* prov_ctx) {
  return osquery::cng_param_types;
}

static int OsqueryCNGGetParams([[maybe_unused]] void* prov_ctx,
                               OSSL_PARAM params[]) {
  OSSL_PARAM* param;

  if (params == nullptr) {
    return 0;
  }

  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
  if (param != nullptr &&
      !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_name))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (param != nullptr &&
      !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_version))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
  if (param != nullptr &&
      !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_buildinfo))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
  if (param != nullptr &&
      !OSSL_PARAM_set_int(param, OsqueryCNGProviderIsRunning()))
    return 0;
  return 1;
}

static const OSSL_ALGORITHM* OsqueryCNGQueryOperations(
    [[maybe_unused]] void* prov_ctx, int operation_id, int* no_store) {
  *no_store = 0;

  switch (operation_id) {
  case OSSL_OP_STORE: {
    std::cout << "Returning store algorithms" << std::endl;
    return OsqueryGetStoreAlgorithms();
  }
  case OSSL_OP_KEYMGMT: {
    std::cout << "Returning CNG KeyMgmt to the core" << std::endl;
    return OsqueryGetKeyManagementAlgorithms();
  }
  case OSSL_OP_SIGNATURE: {
    std::cout << "Returning CNG Signature to core" << std::endl;
    return OsqueryGetSignatureAlgorithms();
  }

  case OSSL_OP_DIGEST:
  case OSSL_OP_CIPHER:
  case OSSL_OP_MAC:
  case OSSL_OP_KDF:
  case OSSL_OP_RAND:
  case OSSL_OP_KEYEXCH:
  case OSSL_OP_ASYM_CIPHER:
  case OSSL_OP_KEM:
  case OSSL_OP_ENCODER:
  case OSSL_OP_DECODER:
    std::cerr << "Operation not supported: " << operation_id << std::endl;
    break;
  default:
    std::cerr << "Error, no algoritm matches: " << operation_id << std::endl;
    return nullptr;
  }
  return nullptr; /* When unsupported return nullptr */
}

static void OsqueryCNGTeardown() {}
}

namespace osquery {
static const OSSL_DISPATCH cng_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGGetTableParams)},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGGetParams)},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGQueryOperations)},
    {OSSL_FUNC_PROVIDER_TEARDOWN,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGTeardown)},
    {0, nullptr}};

} // namespace osquery

extern "C" {
int OsqueryCNGProviderInit([[maybe_unused]] const OSSL_CORE_HANDLE* handle,
                           const OSSL_DISPATCH* in,
                           const OSSL_DISPATCH** out,
                           void** prov_ctx) {
  std::cout << "CNG provider initialized" << std::endl;
  *out = osquery::cng_dispatch_table;

  osquery::CNGProviderCtx* context = nullptr;

  try {
    context = new osquery::CNGProviderCtx();
    *prov_ctx = context;
  } catch (std::bad_alloc&) {
    std::abort();
  }

  context->core_functions = in;

  return 1;
}
}

namespace osquery {

// OpenSSLCNGContext::OpenSSLCNGContext(OSSL_LIB_CTX& lib_ctx,
//                                      OSSL_PROVIDER& default_provider,
//                                      OSSL_PROVIDER& cng_provider) {}

// std::optional<OpenSSLCNGContext> InitializeOpenSSLCNGProvider() {
//   auto* lib_ctx = OSSL_LIB_CTX_new();

//   if (OSSL_PROVIDER_add_builtin(
//           lib_ctx, "cng_provider", OsqueryCNGProviderInit) != 1) {
//     return std::nullopt;
//   }

//   OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(lib_ctx, "default");

//   if (default_provider == nullptr) {
//     return std::nullopt;
//   }

//   OSSL_PROVIDER* cng_provider = OSSL_PROVIDER_load(lib_ctx, "cng_provider");

//   if (cng_provider == nullptr) {
//     return std::nullopt;
//   }

//   return OpenSSLCNGContext{*lib_ctx, *default_provider, *cng_provider};
// }
} // namespace osquery
