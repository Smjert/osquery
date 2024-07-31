/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>
#include <string>

#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <osquery/utils/openssl/darwin/keychain_provider/keychain.h>
#include <osquery/utils/openssl/darwin/keychain_provider/store/store.h>
#include <osquery/utils/openssl/openssl_utils.h>

namespace osquery {

namespace {
std::array<std::string, 2> kStores = {
    "System",
    "SystemRoot",
};
}

SSL_CTX* createNativeContext(
    const NativeOpenSSLParameters& openssl_parameters) {
  auto* ssl_ctx = SSL_CTX_new_ex(&openssl_parameters.getSSLLibraryContext(),
                                 "?provider=keychain_provider",
                                 ::SSLv23_client_method());

  return ssl_ctx;
}

std::optional<OpenSSLProviderContext> createSystemOpenSSLProviderContext() {
  auto* lib_ctx = OSSL_LIB_CTX_new();

  if (OSSL_PROVIDER_add_builtin(
          lib_ctx, "keychain_provider", OsqueryKeychainProviderInit) != 1) {
    return std::nullopt;
  }

  OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(lib_ctx, "default");

  if (default_provider == nullptr) {
    return std::nullopt;
  }

  OSSL_PROVIDER* cng_provider =
      OSSL_PROVIDER_load(lib_ctx, "keychain_provider");

  if (cng_provider == nullptr) {
    return std::nullopt;
  }

  OpenSSLProviderContext provider_context(
      *lib_ctx, *default_provider, *cng_provider);

  return provider_context;
}

X509_STORE* getCABundleFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateFields& search_params) {
  X509_STORE* store = X509_STORE_new();
  for (const auto& store_name : kStores) {
    auto keychain_path = storeNameToPath(store_name);

    SecKeychainRef keychain;
    auto result = SecKeychainOpen(*opt_keychain_path, &keychain);

    if (result != errSecSuccess || keychain == nullptr) {
      return nullptr;
    }

    const void* keychains_values[] = {keychain};
    auto keychains = CFArrayCreate(
        kCFAllocatorDefault, keychains_values, 1, &kCFTypeArrayCallBacks);

    if (keychains == nullptr) {
      return nullptr;
    }

    const void* keys[] = {
        kSecClass, kSecReturnRef, kSecMatchLimit, kSecMatchSearchList};
    const void* values[] = {
        kSecClassCertificate, kCFBooleanTrue, kSecMatchLimitAll, keychains};
    CFDictionaryRef query =
        CFDictionaryCreate(kCFAllocatorDefault,
                           keys,
                           values,
                           sizeof(keys) / sizeof(void*),
                           &kCFCopyStringDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);

    if (query == nullptr) {
      DBGERR("Failed to initialize the certificates query");
      return nullptr;
    }

    CFArrayRef certificates = nullptr;
    OSStatus osStatus = SecItemCopyMatching(query, (CFTypeRef*)&certificates);
    if (osStatus != noErr) {
      DBGERR("Failed to find certificates in store: "
             << store_name << ", error: " << osStatus);
      return nullptr;
    }
  }
}

} // namespace osquery
