/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "keychain.h"

#include <iostream>

#include <osquery/utils/openssl/darwin/keychain_provider/common/defines.h>
#include <osquery/utils/openssl/darwin/keychain_provider/common/provider_context.h>
#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/key_management.h>
#include <osquery/utils/openssl/darwin/keychain_provider/signature/signature.h>
#include <osquery/utils/openssl/darwin/keychain_provider/store/store.h>

#define DBGOUTPUT 0

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl;
#else
#define DBGERR(message)
#endif

namespace osquery {
constexpr const char* provider_name = "Keychain Provider";
constexpr const char* provider_version = "0.0.1";
constexpr const char* provider_buildinfo = "0.0.1";

static const OSSL_PARAM keychain_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, nullptr, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, nullptr, 0),
    OSSL_PARAM_END};
} // namespace osquery

int OsqueryKeychainProviderIsRunning() {
  return 1;
}

static const OSSL_PARAM* OsqueryKeychainGetTableParams(
    [[maybe_unused]] void* prov) {
  return osquery::keychain_param_types;
}

static int OsqueryKeychainGetParams(void* provctx, OSSL_PARAM params[]) {
  OSSL_PARAM* param;

  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
  if (param != NULL && !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_name))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (param != NULL &&
      !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_version))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
  if (param != NULL &&
      !OSSL_PARAM_set_utf8_ptr(param, osquery::provider_buildinfo))
    return 0;
  param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
  if (param != NULL &&
      !OSSL_PARAM_set_int(param, OsqueryKeychainProviderIsRunning()))
    return 0;
  return 1;
}

static const OSSL_ALGORITHM* OsqueryKeychainQueryOperations(
    [[maybe_unused]] void* provctx, int operation_id, int* no_store) {
  *no_store = 0;

  switch (operation_id) {
  case OSSL_OP_STORE: {
    DBGERR("Returning store algorithms");
    return OsqueryKeychainGetStoreAlgorithms();
  }
  case OSSL_OP_KEYMGMT: {
    DBGERR("Returning Keychain KeyMgmt to the core")
    return OsqueryKeychainGetKeyManagementAlgorithms();
  }
  case OSSL_OP_SIGNATURE: {
    DBGERR("Returning Keychain Signature to core")
    return OsqueryKeychainGetSignatureAlgorithms();
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
    DBGERR("Operation not supported")
    break;
  default:
    DBGERR("Error, no algoritm matches")
    return nullptr;
  }
  return nullptr; /* When unsupported return NULL */
}

void OsqueryKeychainTeardown() {}

namespace osquery {
static const OSSL_DISPATCH keychain_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainGetTableParams)},
    {OSSL_FUNC_PROVIDER_GET_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainGetParams)},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainQueryOperations)},
    {OSSL_FUNC_PROVIDER_TEARDOWN,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainTeardown)},
    {0, nullptr}};
}

int OsqueryKeychainProviderInit(const OSSL_CORE_HANDLE* handle,
                                const OSSL_DISPATCH* in,
                                const OSSL_DISPATCH** out,
                                void** prov_ctx) {
  *out = osquery::keychain_dispatch_table;

  osquery::KeychainProviderCtx* context = nullptr;

  try {
    context = new osquery::KeychainProviderCtx();
    *prov_ctx = context;
  } catch (std::bad_alloc&) {
    std::abort();
  }

  context->core_functions = in;

  return 1;
}
