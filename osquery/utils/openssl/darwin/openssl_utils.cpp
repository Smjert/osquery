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
// TODO: remove me
#include <iostream>

#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <Security/Security.h>

#include <osquery/utils/openssl/darwin/keychain_provider/keychain.h>
#include <osquery/utils/openssl/darwin/keychain_provider/store/store.h>
#include <osquery/utils/openssl/openssl_utils.h>

#define DBGOUTPUT 1

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl;
#define DBGWERR(message) std::wcerr << message << std::endl;
#define DBGINFO(message) std::cout << message << std::endl;
#else
#define DBGERR(message)
#define DBGWERR(message)
#define DBGINFO(message)
#endif

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
    auto opt_keychain_path = storeNameToPath(store_name);

    if (!opt_keychain_path.has_value()) {
      return nullptr;
    }

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
    OSStatus os_status =
        SecItemCopyMatching(query, reinterpret_cast<CFTypeRef*>(&certificates));
    if (os_status != noErr) {
      DBGERR("Failed to find certificates in store: "
             << store_name << ", error: " << os_status);
      return nullptr;
    }

    auto certificates_count = CFArrayGetCount(certificates);

    const void* certificate_attributes_keys{kSecOIDX509V1SubjectName};
    for (std::int32_t i = 0; i < certificates_count; ++i) {
      auto certificate =
          (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);
      auto cfArray = CFArrayCreate(
          nullptr, &certificate_attributes_keys, 1, &kCFTypeArrayCallBacks);
      auto certificate_attributes =
          SecCertificateCopyValues(certificate, cfArray, nullptr);

      CFRelease(cfArray);

      if (certificate_attributes != nullptr) {
        CFDictionaryRef subject_attributes =
            (CFDictionaryRef)CFDictionaryGetValue(certificate_attributes,
                                                  kSecOIDX509V1SubjectName);

        std::vector<const void*> keys(CFDictionaryGetCount(subject_attributes));
        std::vector<const void*> values(
            CFDictionaryGetCount(subject_attributes));

        CFDictionaryGetKeysAndValues(
            subject_attributes, keys.data(), values.data());

        for (const auto key : keys) {
          CFTypeID key_id = CFGetTypeID(key);

          std::cout << "Key type: " << key_id << std::endl;

          if (key_id == CFStringGetTypeID()) {
            const CFStringRef key_str = (const CFStringRef)key;
            auto utf16_length = CFStringGetLength(key_str);
            auto length = CFStringGetMaximumSizeForEncoding(
                utf16_length, kCFStringEncodingUTF8);

            if (length == kCFNotFound) {
              std::cerr << "Failed to get string length" << std::endl;
              continue;
            }

            std::string key_c_str(length, '\0');

            CFStringGetCString(key_str,
                               key_c_str.data(),
                               key_c_str.size(),
                               kCFStringEncodingUTF8);

            std::cout << "Key: " << key_c_str << std::endl;
          }
        }
        // CFArrayRef subject_values =
        // (CFArrayRef)CFDictionaryGetValue(subject_attributes,
        // kSecPropertyKeyValue); for (CFIndex i = 0; i <
        // CFArrayGetCount(subject_values); i++) {
        //     CFDictionaryRef element = CFArrayGetValueAtIndex(subject_values,
        //     i); CFStringRef label = CFDictionaryGetValue(element,
        //     kSecPropertyKeyLabel); if (CFStringCompare(label,
        //     CFSTR("2.5.4.3"), 0) == kCFCompareEqualTo) { // OID 2.5.4.3
        //     stands for Common Name
        //         CFStringRef commonName = CFDictionaryGetValue(element,
        //         kSecPropertyKeyValue); NSLog(@"Certificate Common Name: %@",
        //         commonName); break;
        //     }
        // }
      }
    }
  }

  return store;
}

} // namespace osquery
