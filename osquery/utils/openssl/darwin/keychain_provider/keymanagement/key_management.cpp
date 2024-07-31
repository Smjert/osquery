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
    return provider_key->getKeyLengthBits();
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

    if (has_required_features) {
      CFRelease(attributes);
      return 1;
    }

    CFRelease(attributes);
    return 0;
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

  OSSL_PARAM* param = nullptr;

  DBGERR("Attempting to export key at handle "
         << std::hex << provider_key->getHandle() << " with selection "
         << selection << std::dec);

  if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
    // We don't want to export the private key
    return 0;
  }

  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    SecKeyRef public_key = nullptr;
    if (provider_key->getKeyType() == osquery::ProviderKeyType::Private) {
      DBGERR("Requested public key of a private key: "
             << std::hex << provider_key->getHandle() << std::dec);

      public_key = SecKeyCopyPublicKey(provider_key->getHandle());

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

    // CFErrorRef error = nullptr;
    // CFDataRef key_data = SecKeyCopyExternalRepresentation(public_key,
    // &error);

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
      DBGERR("SecItemExport failed: " << error);
      return 0;
    }

    // if (key_data == nullptr) {
    //   // Handle error
    //   if (error) {
    //     CFStringRef error_desc = CFErrorCopyDescription(error);
    //     auto utf16_length = CFStringGetLength(error_desc);
    //     auto length = CFStringGetMaximumSizeForEncoding(utf16_length,
    //                                                     kCFStringEncodingUTF8);

    //     if (length == kCFNotFound) {
    //       CFRelease(error_desc);
    //       CFRelease(error);
    //     }

    //     std::string error_str(length, '\0');

    //     CFStringGetCString(error_desc,
    //                        error_str.data(),
    //                        error_str.size(),
    //                        kCFStringEncodingUTF8);

    //     std::cerr << "Failed to get key representation, Error: " << error_str
    //               << std::endl;
    //     CFRelease(error_desc);
    //     CFRelease(error);
    //   }
    //   return 0;
    // }
    const unsigned char* key_bytes = CFDataGetBytePtr(key_data);
    int key_bytes_len = static_cast<int>(CFDataGetLength(key_data));

    if (key_bytes == nullptr) {
      DBGERR("Failed to get pointer to public key data bytes");
      return 0;
    }

    BIO* bio = BIO_new_mem_buf(key_bytes, key_bytes_len);
    if (bio == nullptr) {
      DBGERR("Failed to allocate BIO");
      return 0;
    }

    // std::cout << "MACOS KEY:" << std::endl;
    // for (auto i = 0; i < key_bytes_len; ++i) {
    //   std::cout << std::setw(2) << std::setfill('0') << std::hex
    //             << (static_cast<std::uint32_t>(key_bytes[i]) & 0xFF);
    //   if (i != 0 && i % 16 == 0) {
    //     std::cout << std::endl;
    //   }
    // }
    // std::cout << std::endl;

    // std::cout << "MACOS ASCII KEY:" << std::endl;
    // std::cout << key_bytes << std::endl;

    // std::cout << "Public key data bytes length: " << std::dec <<
    // key_bytes_len
    //           << std::endl;

    // auto* key = d2i_PublicKey(EVP_PKEY_RSA, nullptr, &key_bytes,
    // key_bytes_len);

    EVP_PKEY* key = d2i_PUBKEY_bio(bio, nullptr);

    if (key == nullptr) {
      DBGERR("Failed to convert macOS key to openssl key");
      CFRelease(key_data);
      return 0;
    }

    BIO_free(bio);

    BIO* keybio = BIO_new(BIO_s_mem());
    DBGERR("Attempting to print public key")
    if (EVP_PKEY_print_public(keybio, key, 0, nullptr) == 1) {
      DBGERR("Exporting public key: ");
      char buffer[1024] = {};
      while (BIO_read(keybio, buffer, 1024) > 0) {
        std::cout << buffer;
      }
    }
    BIO_free(keybio);

    // Extract 'e' and 'n'.
    BIGNUM* n = nullptr;
    BIGNUM* e = nullptr;

    auto res = EVP_PKEY_get_bn_param(key, "n", &n);

    if (res == 0) {
      EVP_PKEY_free(key);
      CFRelease(key_data);
      BN_free(n);
      BN_free(e);
      return 0;
    }

    res = EVP_PKEY_get_bn_param(key, "e", &e);

    if (res == 0) {
      EVP_PKEY_free(key);
      CFRelease(key_data);
      BN_free(n);
      BN_free(e);
      return 0;
    }

    EVP_PKEY_free(key);
    CFRelease(key_data);

    // OSSL_PARAM params[3]{};
    // auto e_size = BN_num_bytes(e);
    // auto n_size = BN_num_bytes(n);
    // std::vector<std::uint8_t> e_bytes(e_size);
    // std::vector<std::uint8_t> n_bytes(n_size);

    // DBGERR("N SIZE: " << n_size);
    // DBGERR("E SIZE: " << e_size);

    // BN_bn2bin(e, e_bytes.data());
    // BN_bn2bin(n, n_bytes.data());

    // BN_free(n);
    // BN_free(e);

    // params[0] = OSSL_PARAM_construct_BN(
    //     OSSL_PKEY_PARAM_RSA_E, e_bytes.data(), e_bytes.size());
    // params[1] = OSSL_PARAM_construct_BN(
    //     OSSL_PKEY_PARAM_RSA_N, n_bytes.data(), n_bytes.size());
    // params[2] = OSSL_PARAM_construct_end();
    // param = params;

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (bld == nullptr) {
      DBGERR("Failed to allocate parameter builder");
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "n", n)) {
      DBGERR("Failed to push N parameter as OSSL_PARAM");
      return 0;
    }

    if (!OSSL_PARAM_BLD_push_BN(bld, "e", e)) {
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

    // OSSL_PARAM params[3];

    // // TODO: this is not correct, params[0].data need to be allocated, see
    // the
    // // export func
    // params[0].key = OSSL_PKEY_PARAM_RSA_E;
    // params[1].key = OSSL_PKEY_PARAM_RSA_N;
    // if (!OSSL_PARAM_set_BN(&params[0], bn_rsa_e) ||
    //     !OSSL_PARAM_set_BN(&params[1], bn_rsa_n)) {
    //   return 0;
    // }

    // params[2] = OSSL_PARAM_construct_end();

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
       "RSA Implementation backed by Windows Keychain"},
      {nullptr, nullptr, nullptr}};

  return key_management_algorithms;
}
