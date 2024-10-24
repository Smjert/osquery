/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "key_management.h"

#include <Security/Security.h>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <vector>

#include <Security/SecItem.h>
#include <Security/SecKeychainItem.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>

#include <osquery/utils/openssl/darwin/keychain_provider/common/defines.h>
#include <osquery/utils/openssl/rsa_utils.h>

#include "provider_key.h"

#define DBGOUTPUT 0

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
void* OsqueryKeychainKeyManagementNew(void* prov_ctx);
void OsqueryKeychainKeyManagementFree(void* key_data);
void* OsqueryKeychainKeyManagementLoad(const void* reference,
                                       size_t reference_size);
int OsqueryKeychainKeyManagementGetParams(void* key_data, OSSL_PARAM params[]);
const OSSL_PARAM* OsqueryKeychainKeyManagementGetTableParams();
int OsqueryKeychainKeyManagementHas(const void* key_data, int selection);
int OsqueryKeychainKeyManagementExport(const void* key_data,
                                       int selection,
                                       OSSL_CALLBACK* param_callback,
                                       void* callback_arg);
const OSSL_PARAM* OsqueryKeychainKeyManagementExportTypes(int selection);
int OsqueryKeychainKeyManagementImport(void* key_data,
                                       int selection,
                                       const OSSL_PARAM params[]);
const OSSL_PARAM* OsqueryKeychainKeyManagementImportTypes(int selection);
}

namespace osquery {

namespace {
static const OSSL_DISPATCH key_management_functions[]{
    {OSSL_FUNC_KEYMGMT_NEW,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementNew)},
    {OSSL_FUNC_KEYMGMT_DUP,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementDup)},
    {OSSL_FUNC_KEYMGMT_FREE,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementFree)},
    {OSSL_FUNC_KEYMGMT_LOAD,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementLoad)},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementGetParams)},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementGetTableParams)},
    {OSSL_FUNC_KEYMGMT_HAS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementHas)},
    {OSSL_FUNC_KEYMGMT_EXPORT,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementExport)},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementExportTypes)},
    {OSSL_FUNC_KEYMGMT_IMPORT,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementImport)},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainKeyManagementImportTypes)},
    {0, nullptr}};
}
} // namespace osquery

void* OsqueryKeychainKeyManagementNew([[maybe_unused]] void* prov_ctx) {
  // TODO: For now we only support RSA keys, but here the key management has to
  // know which key it has to initialize
  return new osquery::ProviderKey{
      0, osquery::ProviderKeyType::Public, osquery::ProviderKeyAlgorithm::RSA};
}

void OsqueryKeychainKeyManagementFree(void* key_data) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  DBGERR("Freeing key: " << std::hex << provider_key->getHandle() << std::dec);

  delete provider_key;
}

void* OsqueryKeychainKeyManagementLoad(const void* reference,
                                       [[maybe_unused]] size_t reference_size) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(reference);

  return OsqueryKeychainKeyManagementDup(provider_key, OSSL_KEYMGMT_SELECT_ALL);
}

int OsqueryKeychainKeyManagementGetParams(void* key_data, OSSL_PARAM params[]) {
  if (key_data == nullptr) {
    return 0;
  }

  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  OSSL_PARAM* param;
  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);

  if (param != nullptr) {
    if (!OSSL_PARAM_set_int(param, provider_key->getKeyLengthBits())) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);

  if (param != nullptr) {
    if (!OSSL_PARAM_set_int(
            param,
            osquery::RSABitsToSecurityBits(provider_key->getKeyLengthBits()))) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);

  if (param != nullptr) {
    // This is documented here
    // https://developer.apple.com/documentation/security/seckeysizes/ksecrsamax?language=objc
    // and here
    // https://opensource.apple.com/source/libsecurity_apple_csp/libsecurity_apple_csp-55003/lib/RSA_DSA_keys.h.auto.html
    if (!OSSL_PARAM_set_int(param, 4096)) {
      return 0;
    }
  }

  return 1;
}

const OSSL_PARAM* OsqueryKeychainKeyManagementGetTableParams() {
  static const OSSL_PARAM key_management_param_types[] = {
      OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_DEFN(
          OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_END};

  return key_management_param_types;
}

int OsqueryKeychainKeyManagementHas(const void* key_data, int selection) {
  bool check_can_decrypt = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
  bool check_can_sign = selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  DBGERR("Checking if key at handle "
         << std::hex << provider_key->getHandle() << " can decrypt: "
         << check_can_decrypt << " can sign: " << check_can_sign << std::dec);

  bool has_required_features = false;
  if (check_can_decrypt || check_can_sign) {
    auto attributes = SecKeyCopyAttributes(provider_key->getHandle());

    if (attributes == nullptr) {
      return 0;
    }

    if (check_can_decrypt) {
      CFBooleanRef can_decrypt = static_cast<CFBooleanRef>(
          CFDictionaryGetValue(attributes, kSecAttrCanDecrypt));
      has_required_features =
          can_decrypt != nullptr && CFBooleanGetValue(can_decrypt);
    }

    if (check_can_sign) {
      CFBooleanRef can_sign = static_cast<CFBooleanRef>(
          CFDictionaryGetValue(attributes, kSecAttrCanSign));
      has_required_features =
          can_sign != nullptr && CFBooleanGetValue(can_sign);
    }

    CFRelease(attributes);

    return has_required_features ? 0 : 1;
  }

  // OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS for RSA keys doesn't exist,
  // so it's fine to return 1.
  // OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS is just something generic,
  // so we return always 1.
  return 1;
}

int OsqueryKeychainKeyManagementExport(const void* key_data,
                                       int selection,
                                       OSSL_CALLBACK* param_callback,
                                       void* callback_arg) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  DBGERR("Attempting to export key at handle "
         << std::hex << provider_key->getHandle() << " with selection "
         << selection << std::dec);

  if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
    // We don't want to export the private key
    return 0;
  }

  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    SecKeyRef public_key = nullptr;

    bool should_release_key = false;
    if (provider_key->getKeyType() == osquery::ProviderKeyType::Private) {
      // We try to export the public part of the private key
      DBGERR("Requested public key of a private key: "
             << std::hex << provider_key->getHandle() << std::dec);

      public_key = SecKeyCopyPublicKey(provider_key->getHandle());
      should_release_key = true;

      if (public_key == nullptr) {
        DBGERR("Failed to find public key from private key: "
               << std::hex << provider_key->getHandle() << std::dec);
        return 0;
      }
      DBGERR("Found public key from private key: " << std::hex << public_key
                                                   << std::dec);
    } else {
      public_key = provider_key->getHandle();
    }

    SecItemImportExportKeyParameters keyParams{};
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    keyParams.passphrase = CFSTR("");

    CFDataRef key_data = nullptr;

    auto error = SecItemExport((SecKeychainItemRef)public_key,
                               kSecFormatOpenSSL,
                               0,
                               &keyParams,
                               &key_data);

    if (error != errSecSuccess) {
      if (should_release_key) {
        CFRelease(public_key);
      }
      DBGERR("SecItemExport failed: " << error);
      return 0;
    }

    const unsigned char* key_bytes = CFDataGetBytePtr(key_data);
    int key_bytes_len = static_cast<int>(CFDataGetLength(key_data));

    if (key_bytes == nullptr) {
      CFRelease(key_data);
      if (should_release_key) {
        CFRelease(public_key);
      }
      DBGERR("Failed to get pointer to public key data bytes");
      return 0;
    }

    if (should_release_key) {
      CFRelease(public_key);
    }

    BIO* bio = BIO_new_mem_buf(key_bytes, key_bytes_len);
    if (bio == nullptr) {
      CFRelease(key_data);
      DBGERR("Failed to allocate BIO");
      return 0;
    }

    EVP_PKEY* key = d2i_PUBKEY_bio(bio, nullptr);

    if (key == nullptr) {
      DBGERR("Failed to convert macOS key to openssl key");
      CFRelease(key_data);
      BIO_free(bio);
      return 0;
    }

    BIO_free(bio);
    CFRelease(key_data);

    // Extract 'e' and 'n'.
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;

    auto res = EVP_PKEY_get_bn_param(key, "n", &n);

    if (res == 0) {
      EVP_PKEY_free(key);
      BN_free(n);
      BN_free(e);
      return 0;
    }

    res = EVP_PKEY_get_bn_param(key, "e", &e);

    if (res == 0) {
      EVP_PKEY_free(key);
      BN_free(n);
      BN_free(e);
      return 0;
    }

    EVP_PKEY_free(key);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (bld == nullptr) {
      DBGERR("Failed to allocate parameter builder");
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "n", n)) {
      DBGERR("Failed to push N parameter as OSSL_PARAM");
      OSSL_PARAM_BLD_free(bld);
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "e", e)) {
      DBGERR("Failed to push E parameter as OSSL_PARAM");
      OSSL_PARAM_BLD_free(bld);
      return 0;
    }

    // Convert the OSSL_PARAM_BLD to an OSSL_PARAM array
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    if (params == nullptr) {
      DBGERR("Failed to convert param builder to param array");
      OSSL_PARAM_BLD_free(bld);
      return 0;
    }

    OSSL_PARAM_BLD_free(bld);

    DBGERR("Successful export of key at handle: "
           << std::hex << provider_key->getHandle() << " with selection "
           << selection << std::dec);

    /* NOTE: we return here because this is the only type of selection
       we support now */
    return param_callback(params, callback_arg);
  }

  /*
    Here we should never arrive if the function has to be successful,
    but these are a couple of other examples of selections that we could
    be asked for.
    RSA keys don't have the domain parameter.

  if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
    return 0;
  }

  if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
    return 0;
  }*/

  return 0;
}

const OSSL_PARAM* OsqueryKeychainKeyManagementExportTypes(int selection) {
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    static const OSSL_PARAM export_param_table[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
        OSSL_PARAM_END};
    return export_param_table;
  } else {
    return nullptr;
  }
}

const OSSL_PARAM* OsqueryKeychainKeyManagementImportTypes(int selection) {
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    static const OSSL_PARAM import_param_table[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
        OSSL_PARAM_END};
    return import_param_table;
  } else {
    return nullptr;
  }
}

/*
  Imports a public key into our key management in an ephemeral way.
  This is needed when openssl receives a peer certificate through TLS
  communication, which is in the openssl built-in format, and want to convert it
  in our provider form, so that it can later use it with our functions.

  TODO: This import function for now is RSA specific.
*/
int OsqueryKeychainKeyManagementImport(void* key_data,
                                       int selection,
                                       const OSSL_PARAM params[]) {
  DBGERR("Trying to import a key of type: " << selection);
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    const OSSL_PARAM* rsa_e =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    const OSSL_PARAM* rsa_n =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);

    if (rsa_e == nullptr || rsa_n == nullptr) {
      return 0;
    }

    BIGNUM* bn_rsa_n = nullptr;
    auto res = OSSL_PARAM_get_BN(rsa_n, &bn_rsa_n);

    if (res == 0) {
      return 0;
    }

    BIGNUM* bn_rsa_e = nullptr;
    res = OSSL_PARAM_get_BN(rsa_e, &bn_rsa_e);

    if (res == 0) {
      return 0;
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (bld == nullptr) {
      DBGERR("Failed to allocate parameter builder");
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "n", bn_rsa_n)) {
      DBGERR("Failed to push N parameter as OSSL_PARAM");
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "e", bn_rsa_e)) {
      DBGERR("Failed to push E parameter as OSSL_PARAM");
      return 0;
    }

    // Convert the OSSL_PARAM_BLD to an OSSL_PARAM array
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    if (params == nullptr) {
      DBGERR("Failed to convert param builder to param array");
      return 0;
    }

    OSSL_PARAM_BLD_free(bld);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);

    if (ctx == nullptr) {
      return 0;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
      EVP_PKEY_CTX_free(ctx);
      return 0;
    }

    EVP_PKEY* pkey = nullptr;
    if (!EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params)) {
      EVP_PKEY_CTX_free(ctx);
      return 0;
    }

    auto key_raw_data_size = i2d_PublicKey(pkey, nullptr);
    std::vector<std::uint8_t> key_raw_data(key_raw_data_size);
    std::uint8_t* p = key_raw_data.data();
    if (i2d_PublicKey(pkey, &p) < 0) {
      EVP_PKEY_free(pkey);
      EVP_PKEY_CTX_free(ctx);
      return 0;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    CFDataRef keyData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                                    key_raw_data.data(),
                                                    key_raw_data.size(),
                                                    kCFAllocatorNull);

    // Prepare attributes for SecKey creation
    CFMutableDictionaryRef keyAttributes =
        CFDictionaryCreateMutable(nullptr,
                                  2,
                                  &kCFTypeDictionaryKeyCallBacks,
                                  &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(keyAttributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(
        keyAttributes, kSecAttrKeyClass, kSecAttrKeyClassPublic);

    CFErrorRef error = nullptr;
    SecKeyRef publicKey = SecKeyCreateWithData(keyData, keyAttributes, &error);

    if (publicKey == nullptr) {
      return 0;
    }

    osquery::ProviderKey* provider_key =
        static_cast<osquery::ProviderKey*>(key_data);

    *provider_key = osquery::ProviderKey(publicKey,
                                         osquery::ProviderKeyType::Public,
                                         osquery::ProviderKeyAlgorithm::RSA);

    DBGERR("Successfully imported a key!");

    return 1;
  }

  return 0;
}

void* OsqueryKeychainKeyManagementDup(const void* keydata_from,
                                      [[maybe_unused]] int selection) {
  const osquery::ProviderKey* old_key_data =
      static_cast<const osquery::ProviderKey*>(keydata_from);

  auto* new_key_data = old_key_data->clone();

  if (new_key_data == nullptr) {
    DBGERR("Failed to duplicate key handle "
           << std::hex << old_key_data->getHandle() << std::dec);
    return nullptr;
  }

  DBGERR("Duplicated key handle " << std::hex << old_key_data->getHandle()
                                  << " to " << new_key_data->getHandle()
                                  << std::dec);

  return new_key_data;
}

const OSSL_ALGORITHM* OsqueryKeychainGetKeyManagementAlgorithms() {
  static const OSSL_ALGORITHM key_management_algorithms[]{
      {"rsaEncryption",
       osquery::algorithm_properties,
       osquery::key_management_functions,
       "RSA Implementation backed by macOS Keychain"},
      {nullptr, nullptr, nullptr}};

  return key_management_algorithms;
}
