/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "store.h"

#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFData.h>
#include <CoreFoundation/CFDictionary.h>
#include <Security/Security.h>

#include <cstring>
#include <iostream>
#include <vector>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>

#include <osquery/utils/openssl/darwin/keychain_provider/common/defines.h>

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

extern "C" {
void* OsqueryKeychainStoreOpen(void* prov_ctx, const char* uri);
int OsqueryKeychainSetCtxParams(void* loader_ctx, const OSSL_PARAM params[]);
int OsqueryKeychainStoreLoad(void* loaderctx,
                             OSSL_CALLBACK* object_callback,
                             void* object_callback_arg,
                             OSSL_PASSPHRASE_CALLBACK* pw_cb,
                             void* pw_cbarg);
int OsqueryKeychainStoreEof(void* loader_ctx);
int OsqueryKeychainStoreClose(void* loader_ctx);
}

namespace osquery {
namespace {

const std::string kUriAlgorithmPrefix = "keychain://";
const char* kSystemRootsKeychainPath =
    "/System/Library/Keychains/SystemRootCertificates.keychain";

static const OSSL_DISPATCH keychain_store_functions[]{
    {OSSL_FUNC_STORE_OPEN,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainStoreOpen)},
    {OSSL_FUNC_STORE_LOAD,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainStoreLoad)},
    {OSSL_FUNC_STORE_EOF,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainStoreEof)},
    {OSSL_FUNC_STORE_CLOSE,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainStoreClose)},
    {0, nullptr}};

} // namespace
} // namespace osquery

void* OsqueryKeychainStoreOpen(void* prov_ctx, const char* uri) {
  if (prov_ctx == nullptr || uri == nullptr) {
    return nullptr;
  }

  auto uri_length = strlen(uri);

  // The URI should contain the prefix and at least one character for the store
  if (uri_length < (osquery::kUriAlgorithmPrefix.size() + 1)) {
    return nullptr;
  }

  const std::string_view uri_string(uri, uri_length);
  if (uri_string.compare(0,
                         osquery::kUriAlgorithmPrefix.size(),
                         osquery::kUriAlgorithmPrefix) != 0) {
    return nullptr;
  }

  const char* store_name = (uri + osquery::kUriAlgorithmPrefix.size());
  auto length = uri_length - osquery::kUriAlgorithmPrefix.size();

  std::string_view store_name_view(&store_name[0], length);

  auto store = osquery::Store::openStore(store_name_view);

  return store;
}

int OsqueryKeychainStoreLoad(void* loader_ctx,
                             OSSL_CALLBACK* object_callback,
                             void* object_callback_arg,
                             [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK* pw_cb,
                             [[maybe_unused]] void* pw_cbarg) {
  if (loader_ctx == nullptr) {
    return 0;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  auto res = store->loadNextCertificate(object_callback, object_callback_arg);

  if (!res) {
    res = store->loadNextPrivateKey(object_callback, object_callback_arg);
  }

  return res;
}

int OsqueryKeychainStoreEof(void* loader_ctx) {
  if (loader_ctx == nullptr) {
    return 1;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  return store->isStoreAtEof();
}

int OsqueryKeychainStoreClose(void* loader_ctx) {
  if (loader_ctx == nullptr) {
    return 1;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  if (!store->close()) {
    return 0;
  }

  delete store;

  return 1;
}

const OSSL_ALGORITHM* OsqueryKeychainGetStoreAlgorithms() {
  static const OSSL_ALGORITHM keychain_store[] = {
      {"keychain",
       osquery::algorithm_properties,
       osquery::keychain_store_functions,
       "Keychain Provider Implementation"},
      {nullptr, nullptr, nullptr}};

  return keychain_store;
}

namespace osquery {
namespace {
/*NCRYPT_KEY_HANDLE loadPrivateKeyFromCert(PCCERT_CONTEXT cert) {
  DWORD key_spec = 0;
  BOOL caller_must_free = FALSE;
  NCRYPT_KEY_HANDLE tmp_key_handle = 0;
  BOOL retval = CryptAcquireCertificatePrivateKey(
      cert,
      CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
      nullptr,
      &tmp_key_handle,
      &key_spec,
      &caller_must_free);

  if (retval != TRUE) {
    std::wstring subject_name;
    DWORD subject_size = 0;
    DWORD error = GetLastError();

    auto res = CertNameToStrW(X509_ASN_ENCODING,
                              &cert->pCertInfo->Subject,
                              CERT_SIMPLE_NAME_STR,
                              nullptr,
                              subject_size);

    if (res != 0) {
      subject_size = res;
      subject_name.resize(subject_size);

      res = CertNameToStrW(X509_ASN_ENCODING,
                           &cert->pCertInfo->Subject,
                           CERT_SIMPLE_NAME_STR,
                           subject_name.data(),
                           subject_size);
      if (res == 0) {
        DBGERR("Failed to get the certificate subject name");
      } else {
        subject_name.pop_back();
      }
    } else {
      DBGERR("Failed to get the certificate subject name size");
    }

    DBGWERR("Failed to load private key from certificate "
            << subject_name << ", error: " << std::hex << error << std::dec);
  }

  if (caller_must_free != TRUE) {
    return 0;
  }

  DBGERR("Loading key handle: " << std::hex << tmp_key_handle << std::dec);

  return tmp_key_handle;
}*/

std::optional<ProviderKeyAlgorithm> getKeyAlgorithmType(const SecKeyRef key) {
  CFDictionaryRef attrs = SecKeyCopyAttributes(key);

  if (attrs == nullptr) {
    return std::nullopt;
  }

  const void* keyTypeValue = CFDictionaryGetValue(attrs, kSecAttrKeyType);
  CFRelease(attrs);

  if (keyTypeValue != kSecAttrKeyTypeRSA) {
    return std::nullopt;
  }

  return ProviderKeyAlgorithm::RSA;
}

std::optional<ProviderKey> searchNextValidPrivateKey(
    SecKeychainRef keychain,
    CFArrayRef certificates,
    std::size_t& current_certificate_idx) {
  auto certificates_count = CFArrayGetCount(certificates);

  const std::array<const void*, 3> keys = {
      kSecClass, kSecReturnRef, kSecValueRef};
  std::array<const void*, 3> values = {
      kSecClassIdentity, kCFBooleanTrue, nullptr};
  auto dict = CFDictionaryCreateMutable(nullptr,
                                        keys.size(),
                                        &kCFTypeDictionaryKeyCallBacks,
                                        &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(dict, kSecClass, kSecClassIdentity);
  CFDictionaryAddValue(dict, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(dict, kSecValueRef, kCFNull);

  std::optional<ProviderKeyAlgorithm> opt_key_algorithm;
  SecKeyRef private_key = nullptr;

  for (; current_certificate_idx < certificates_count && private_key == nullptr;
       ++current_certificate_idx) {
    DBGINFO("Privkey cert index " << current_certificate_idx);
    auto cert = (SecCertificateRef)CFArrayGetValueAtIndex(
        certificates, current_certificate_idx);
    CFDictionarySetValue(dict, kSecValueRef, cert);

    SecIdentityRef identity = nullptr;
    OSStatus status = SecItemCopyMatching(dict, (CFTypeRef*)&identity);

    if (status != errSecSuccess || identity == nullptr) {
      continue;
    }

    // Extract the private key from the identity
    SecKeyRef current_private_key = nullptr;
    status = SecIdentityCopyPrivateKey(identity, &current_private_key);
    if (status != errSecSuccess) {
      continue;
    }

    opt_key_algorithm = getKeyAlgorithmType(current_private_key);

    // This means the algorithm of the key is not supported
    if (!opt_key_algorithm.has_value()) {
      continue;
    }

    CFStringRef certSummary = SecCertificateCopySubjectSummary(cert);
    char certSummaryBuf[512];
    DBGINFO("Found private key: " << std::hex << current_private_key
                                  << std::dec)
    if (CFStringGetCString(certSummary,
                           certSummaryBuf,
                           sizeof(certSummaryBuf),
                           kCFStringEncodingASCII)) {
      DBGINFO("From certificate: " << certSummaryBuf);
    }

    CFRelease(certSummary);
    private_key = current_private_key;
  }

  if (private_key == nullptr) {
    DBGINFO("End of private key store");
    return std::nullopt;
  }

  return ProviderKey(private_key, ProviderKeyType::Private, *opt_key_algorithm);
}
} // namespace

std::optional<const char*> storeNameToPath(std::string_view store_name) {
  const char* keychain_path = nullptr;
  if (store_name == "System") {
    keychain_path = kSystemKeychainPath;
  } else if (store_name == "SystemRoot") {
    keychain_path = kSystemRootsKeychainPath;
  }
  // Unsupported
  return std::nullopt;
}

Store* Store::openStore(std::string_view store_name) {
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
  OSStatus osStatus = SecItemCopyMatching(query, (CFTypeRef*)&certificates);
  if (osStatus != noErr) {
    DBGERR("Failed to find certificates in store: " << store_name
                                                    << ", error: " << osStatus);
    return nullptr;
  }

  std::size_t current_key_certificate_idx = 0;

  // CFIndex count = CFArrayGetCount(result);
  // for (CFIndex i = 0; i < count; i++) {
  //   SecCertificateRef certRef =
  //       static_cast<SecCertificateRef>(CFArrayGetValueAtIndex(result, i));
  //   CFStringRef certSummary = SecCertificateCopySubjectSummary(certRef);
  //   char certSummaryBuf[256];
  //   if (CFStringGetCString(certSummary,
  //                          certSummaryBuf,
  //                          sizeof(certSummaryBuf),
  //                          kCFStringEncodingASCII)) {
  //     printf("Cert Name: %s\n", certSummaryBuf);
  //   }
  //   CFRelease(certSummary);
  // }
  // CFRelease(result);

  auto opt_private_key = searchNextValidPrivateKey(
      keychain, certificates, current_key_certificate_idx);

  auto* store = new Store(keychain,
                          certificates,
                          current_key_certificate_idx,
                          std::move(opt_private_key));

  return store;
}

Store::Store(SecKeychainRef keychain,
             CFArrayRef certificates,
             std::size_t current_key_certificate_idx,
             std::optional<ProviderKey> first_private_key)
    : keychain_(keychain),
      certificates_(certificates),
      current_certificate_idx_(0),
      certificates_eof_(CFArrayGetCount(certificates_) <=
                        current_certificate_idx_),
      current_key_certificate_idx_(current_key_certificate_idx),
      current_private_key_(std::move(first_private_key)) {}

Store::~Store() {
  close();
}

bool Store::loadNextPrivateKey(OSSL_CALLBACK* object_callback,
                               void* object_callback_arg) {
  if (!current_private_key_.has_value()) {
    return false;
  }

  ProviderKeyAlgorithm algorithm = current_private_key_->getKeyAlgorithm();

  const char* key_algorithm = [&algorithm]() -> const char* {
    switch (algorithm) {
    case ProviderKeyAlgorithm::RSA: {
      return "rsaEncryption";
    }
    }

    return nullptr;
  }();

  // This should not happen, but lets be sure
  if (key_algorithm == nullptr) {
    return false;
  }

  static int object_type_pkey = OSSL_OBJECT_PKEY;
  OSSL_PARAM privkey_params[] = {
      OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &object_type_pkey),
      /* When given the string length 0, OSSL_PARAM_utf8_string() figures out
         the real length */
      OSSL_PARAM_utf8_string(
          OSSL_OBJECT_PARAM_DATA_TYPE,
          const_cast<void*>(reinterpret_cast<const void*>(key_algorithm)),
          0),
      /* Here we MUST use a reference, because this is not a real RSA private
         key, but just a handle. This forces openssl to make a duplicate of
         the key handle and therefore keep its own copy alive, otherwise when
         we close the store, the key handle is destroyed */
      OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                              &current_private_key_,
                              sizeof(ProviderKey*)),
      OSSL_PARAM_END};

  if (object_callback(privkey_params, object_callback_arg) == 0) {
    return false;
  }

  current_private_key_ = searchNextValidPrivateKey(
      keychain_, certificates_, current_key_certificate_idx_);

  return true;
}

bool Store::loadNextCertificate(OSSL_CALLBACK* object_callback,
                                void* object_callback_arg) {
  if (certificates_eof_ == true) {
    return false;
  }

  SecCertificateRef current_certificate =
      (SecCertificateRef)CFArrayGetValueAtIndex(certificates_,
                                                current_certificate_idx_);

  if (current_certificate == nullptr) {
    return false;
  }

  CFDataRef certificate_data = SecCertificateCopyData(current_certificate);

  if (certificate_data == nullptr) {
    return false;
  }

  static constexpr auto object_type_cert = OSSL_OBJECT_CERT;
  OSSL_PARAM cert_params[] = {
      OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE,
                     const_cast<int*>(&object_type_cert)),
      OSSL_PARAM_octet_string(
          OSSL_OBJECT_PARAM_DATA,
          (void*)CFDataGetBytePtr(certificate_data),
          static_cast<std::size_t>(CFDataGetLength(certificate_data))),
      OSSL_PARAM_END};
  object_callback(cert_params, object_callback_arg);

  ++current_certificate_idx_;

  if (current_certificate_idx_ >= CFArrayGetCount(certificates_)) {
    certificates_eof_ = true;
  }

  return true;
}

bool Store::close() {
  bool success = true;
  if (keychain_ != nullptr) {
    CFRelease(certificates_);
    current_private_key_ = std::nullopt;
    current_certificate_idx_ = 0;
    current_key_certificate_idx_ = 0;
    certificates_eof_ = true;
    CFRelease(keychain_);
    keychain_ = nullptr;
  }
  return success;
}

} // namespace osquery
