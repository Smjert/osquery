/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "signature.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <osquery/utils/openssl/darwin/keychain_provider/common/defines.h>
#include <osquery/utils/openssl/darwin/keychain_provider/common/provider_context.h>
#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/key_management.h>
#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/provider_key.h>
#include <osquery/utils/openssl/darwin/keychain_provider/signature/signature_ctx.h>

#define DBGOUTPUT 0

#if DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl
#define DBGWERR(message) std::wcerr << message << std::endl
#define DBGINFO(message) std::cout << message << std::endl
#else
#define DBGERR(message)
#define DBGWERR(message)
#define DBGINFO(messsage)
#endif

extern "C" {
void* OsqueryKeychainSignatureNewCtx(void* prov_ctx,
                                     const char* prop_query) noexcept;
void* OsqueryKeychainSignatureDupCtx(void* ctx) noexcept;
void OsqueryKeychainSignatureFreeCtx(void* ctx) noexcept;
int OsqueryKeychainSignatureDigestSignInit(void* ctx,
                                           const char* digest_name,
                                           void* prov_key,
                                           const OSSL_PARAM params[]) noexcept;
int OsqueryKeychainSignatureDigestSignUpdate(void* ctx,
                                             const unsigned char* data,
                                             size_t data_len) noexcept;
int OsqueryKeychainSignatureDigestSignFinal(void* ctx,
                                            unsigned char* sig,
                                            size_t* sig_len,
                                            size_t sig_size) noexcept;
int OsqueryKeychainSignatureDigestVerifyInit(
    void* ctx,
    const char* digest_name,
    void* prov_key,
    const OSSL_PARAM params[]) noexcept;
int OsqueryKeychainSignatureDigestVerifyUpdate(void* ctx,
                                               const unsigned char* data,
                                               size_t data_len) noexcept;
int OsqueryKeychainSignatureDigestVerifyFinal(void* ctx,
                                              unsigned char* sig,
                                              size_t sig_len) noexcept;
int OsqueryKeychainSignatureSetCtxMdParams(void* ctx,
                                           const OSSL_PARAM params[]) noexcept;
const OSSL_PARAM* OsqueryKeychainSignatureSettableCtxParams(
    void* ctx, void* prov_ctx) noexcept;

int OsqueryKeychainSignatureSetCtxParams(void* ctx,
                                         const OSSL_PARAM params[]) noexcept;
const OSSL_PARAM* OsqueryKeychainSignatureSettableCtxMdParams(
    void* ctx, void* prov_ctx) noexcept;
}

namespace osquery {
namespace {

const OSSL_DISPATCH signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainSignatureNewCtx)},
    {OSSL_FUNC_SIGNATURE_DUPCTX,
     reinterpret_cast<OSSLKeychainFunctionPtr>(OsqueryKeychainSignatureDupCtx)},
    {OSSL_FUNC_SIGNATURE_FREECTX,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureFreeCtx)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestSignInit)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestSignUpdate)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestSignFinal)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestVerifyInit)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestVerifyUpdate)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureDigestVerifyFinal)},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureSetCtxParams)},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureSettableCtxParams)},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureSetCtxMdParams)},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
     reinterpret_cast<OSSLKeychainFunctionPtr>(
         OsqueryKeychainSignatureSettableCtxMdParams)},
    {0, nullptr}};

std::optional<std::int32_t> getExpectedPSSSaltLength(
    SecKeyAlgorithm algorithm_id) {
  if (algorithm_id == kSecKeyAlgorithmRSASignatureDigestPSSSHA256) {
    return 32;
  }

  if (algorithm_id == kSecKeyAlgorithmRSASignatureDigestPSSSHA384) {
    return 48;
  }

  if (algorithm_id == kSecKeyAlgorithmRSASignatureDigestPSSSHA512) {
    return 64;
  }
  return std::nullopt;
}

std::optional<SecKeyAlgorithm> hashAndPaddingToSignAlgorithm(
    EVP_MD_CTX* hash_ctx, SignaturePadding padding) {
  const EVP_MD* md = EVP_MD_CTX_get0_md(hash_ctx);

  switch (padding) {
  case SignaturePadding::Pkcs1: {
    if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_256)) {
      return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
    } else if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_384)) {
      return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
    } else if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_512)) {
      return kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
    }

    return std::nullopt;
  }
  case SignaturePadding::Pss: {
    if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_256)) {
      return kSecKeyAlgorithmRSASignatureDigestPSSSHA256;
    } else if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_384)) {
      return kSecKeyAlgorithmRSASignatureDigestPSSSHA384;
    } else if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_512)) {
      return kSecKeyAlgorithmRSASignatureDigestPSSSHA512;
    }
  }
  case SignaturePadding::None: {
    return std::nullopt;
  }
  }

  return std::nullopt;
}

} // namespace
} // namespace osquery

void* OsqueryKeychainSignatureNewCtx(
    [[maybe_unused]] void* prov_ctx,
    [[maybe_unused]] const char* prop_query) noexcept {
  if (prop_query != nullptr) {
    DBGINFO("New signature propquery: " << prop_query);
  }

  return new osquery::SignatureCtx();
}

void* OsqueryKeychainSignatureDupCtx(void* ctx) noexcept {
  osquery::SignatureCtx* old_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  return old_ctx->clone();
}

void OsqueryKeychainSignatureFreeCtx(void* ctx) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  delete sig_ctx;
}

int OsqueryKeychainSignatureDigestSignInit(void* ctx,
                                           const char* digest_name,
                                           void* prov_key,
                                           const OSSL_PARAM params[]) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);
  if (sig_ctx == nullptr || digest_name == nullptr || prov_key == nullptr) {
    return 0;
  }

  return sig_ctx->initHash(digest_name,
                           *static_cast<osquery::ProviderKey*>(prov_key)) &&
         sig_ctx->updateParams(params);
}

int OsqueryKeychainSignatureDigestSignUpdate(void* ctx,
                                             const unsigned char* data,
                                             size_t data_len) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || data == nullptr) {
    return 0;
  }

  return sig_ctx->updateHash(data, data_len);
}

int OsqueryKeychainSignatureDigestSignFinal(void* ctx,
                                            unsigned char* sig,
                                            size_t* sig_len,
                                            size_t sig_size) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || sig_len == nullptr) {
    return 0;
  }

  if (sig == nullptr) {
    *sig_len = sig_ctx->getSignatureLength();

    return 1;
  }

  return sig_ctx->finishHashAndSign(sig, *sig_len, sig_size);
}

int OsqueryKeychainSignatureDigestVerifyInit(
    void* ctx,
    const char* digest_name,
    void* prov_key,
    const OSSL_PARAM params[]) noexcept {
  return OsqueryKeychainSignatureDigestSignInit(
      ctx, digest_name, prov_key, params);
}

int OsqueryKeychainSignatureDigestVerifyUpdate(void* ctx,
                                               const unsigned char* data,
                                               size_t data_len) noexcept {
  return OsqueryKeychainSignatureDigestSignUpdate(ctx, data, data_len);
}
int OsqueryKeychainSignatureDigestVerifyFinal(void* ctx,
                                              unsigned char* sig,
                                              size_t sig_len) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || sig == nullptr || sig_len == 0) {
    return 0;
  }

  return sig_ctx->finishHashAndVerifySignature(sig, sig_len);
}

int OsqueryKeychainSignatureSetCtxParams(void* ctx,
                                         const OSSL_PARAM params[]) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr) {
    return 0;
  }

  return sig_ctx->updateParams(params);
}

const OSSL_PARAM* OsqueryKeychainSignatureSettableCtxParams(
    [[maybe_unused]] void* ctx, [[maybe_unused]] void* prov_ctx) noexcept {
  static OSSL_PARAM settable[] = {
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, nullptr, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, nullptr, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, nullptr, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, nullptr, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, nullptr, 0),
      OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nullptr, 0),
      OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, nullptr),
      OSSL_PARAM_END};
  return settable;
}

int OsqueryKeychainSignatureSetCtxMdParams(void* ctx,
                                           const OSSL_PARAM params[]) noexcept {
  return OsqueryKeychainSignatureSetCtxParams(ctx, params);
}

const OSSL_PARAM* OsqueryKeychainSignatureSettableCtxMdParams(
    void* ctx, void* prov_ctx) noexcept {
  return OsqueryKeychainSignatureSettableCtxParams(ctx, prov_ctx);
}

const OSSL_ALGORITHM* OsqueryKeychainGetSignatureAlgorithms() {
  static const OSSL_ALGORITHM signature[] = {
      {"RSA:rsaEncryption",
       osquery::algorithm_properties,
       osquery::signature_functions,
       "RSA signature implementation backed by macOS SecKey"},
      /* Other algorithm names include (but are not limited to) ED25519, ED448,
         EC:id-ecPublicKey, DSA, X25519 */
      {nullptr, nullptr, nullptr}};

  return signature;
}

namespace osquery {
SignatureCtx::~SignatureCtx() {
  EVP_MD_CTX_free(hash_ctx_);
  hash_ctx_ = nullptr;

  delete provider_key_;
  provider_key_ = nullptr;
}

bool SignatureCtx::initHash(const char* digest_name, ProviderKey& key) {
  EVP_MD* hash_type = EVP_MD_fetch(nullptr, digest_name, nullptr);
  if (hash_type == nullptr) {
    return false;
  }

  EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();

  if (hash_ctx == nullptr) {
    return false;
  }

  auto res = EVP_DigestInit(hash_ctx, hash_type);

  if (res == 0) {
    return false;
  }

  EVP_MD_free(hash_type);

  hash_ctx_ = hash_ctx;
  provider_key_ = key.clone();

  DBGERR("Initializing hash handle: " << std::hex << hash_ctx_ << " and key: "
                                      << key.getHandle() << std::dec);

  return true;
}

bool SignatureCtx::updateHash(const unsigned char* data, size_t data_len) {
  DBGERR("Updating hash handle: " << std::hex << hash_ctx_ << std::dec);

  return EVP_DigestUpdate(hash_ctx_, data, data_len);
}

std::size_t SignatureCtx::getSignatureLength() {
  return provider_key_->getKeyLengthBits() / 8;
}

bool SignatureCtx::finishSignature(
    std::basic_string_view<std::uint8_t> hash_data,
    std::size_t max_signature_length,
    unsigned char* signature,
    std::size_t& actual_signature_length) {
  CFDataRef cf_hash = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                                  hash_data.data(),
                                                  hash_data.size(),
                                                  kCFAllocatorNull);

  if (cf_hash == nullptr) {
    DBGERR("Failed to create CFData from buffer for signature");
    return false;
  }

  // TODO: Handle the error or don't pass it
  CFErrorRef error = nullptr;
  CFDataRef cf_signature = SecKeyCreateSignature(
      provider_key_->getHandle(), algorithm_id_, cf_hash, &error);

  CFRelease(cf_hash);

  if (cf_signature == nullptr) {
#if DBGOUTPUT
    CFStringRef error_desc = CFErrorCopyDescription(error);
    auto utf16_length = CFStringGetLength(error_desc);
    auto length =
        CFStringGetMaximumSizeForEncoding(utf16_length, kCFStringEncodingUTF8);

    if (length == kCFNotFound) {
      CFRelease(error_desc);
      CFRelease(error);
    }

    std::string error_str(length, '\0');

    CFStringGetCString(
        error_desc, error_str.data(), error_str.size(), kCFStringEncodingUTF8);

    DBGERR("Failed to create Signature: ") << error_str << "\n";

    CFRelease(error_desc);
#endif
    CFRelease(error);
    return false;
  }

  DBGINFO("Successfully signed hash");

  std::stringstream ss;

  for (auto b : hash_data) {
    ss << std::setw(2) << std::setfill('0') << std::hex
       << (static_cast<std::uint32_t>(b) & 0xFF);
  }

  DBGINFO(ss.rdbuf());

  actual_signature_length = CFDataGetLength(cf_signature);
  CFDataGetBytes(
      cf_signature, CFRangeMake(0, actual_signature_length), signature);

  CFRelease(cf_signature);

  return true;
}

bool SignatureCtx::finishHashAndSign(unsigned char* signature,
                                     std::size_t& actual_signature_length,
                                     std::size_t max_signature_length) {
  std::vector<std::uint8_t> hash_data(EVP_MAX_MD_SIZE);

  DBGINFO("Finish Hash Signature with handle: " << std::hex << hash_ctx_
                                                << std::dec);

  std::uint32_t hash_size = 0;
  if (!EVP_DigestFinal(hash_ctx_, hash_data.data(), &hash_size)) {
    DBGERR("Failed to finish hash with error: "
           << std::hex << ERR_peek_last_error() << std::dec);
    return false;
  }

  hash_data.resize(hash_size);

  return finishSignature(
      std::basic_string_view<std::uint8_t>(hash_data.data(), hash_data.size()),
      max_signature_length,
      signature,
      actual_signature_length);
}

bool SignatureCtx::finishHashAndVerifySignature(unsigned char* signature,
                                                std::size_t signature_length) {
  std::vector<std::uint8_t> hash_data(EVP_MAX_MD_SIZE);

  DBGINFO("Finish Hash to verify with handle: " << std::hex << hash_ctx_
                                                << std::dec);

  std::uint32_t hash_size = 0;
  if (!EVP_DigestFinal(hash_ctx_, hash_data.data(), &hash_size)) {
    DBGERR("Failed to finish hash with error: "
           << std::hex << ERR_peek_last_error() << std::dec);
    return false;
  }

  hash_data.resize(hash_size);

  CFDataRef cf_hash = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                                  hash_data.data(),
                                                  hash_data.size(),
                                                  kCFAllocatorNull);

  if (cf_hash == nullptr) {
    return false;
  }

  CFDataRef cf_signature = CFDataCreateWithBytesNoCopy(
      kCFAllocatorDefault, signature, signature_length, kCFAllocatorNull);

  if (cf_signature == nullptr) {
    CFRelease(cf_hash);
    return false;
  }

  CFErrorRef error = nullptr;
  bool valid_signature = SecKeyVerifySignature(
      provider_key_->getHandle(), algorithm_id_, cf_hash, cf_signature, &error);

  CFRelease(cf_signature);
  CFRelease(cf_hash);

  if (error != nullptr) {
    CFRelease(error);
    return false;
  }

  return valid_signature;
}

bool SignatureCtx::updateParams(const OSSL_PARAM params[]) {
  auto new_padding = padding_;

  DBGINFO("Starting padding is: " << static_cast<std::int32_t>(new_padding));
  if (params != nullptr) {
    // Get pad mode parameter
    const OSSL_PARAM* param =
        OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);

    if (param != nullptr) {
      switch (param->data_type) {
      case OSSL_PARAM_INTEGER: {
        int pad_mode = 0;

        if (param->data_size != sizeof(pad_mode)) {
          return false;
        }

        std::memcpy(&pad_mode, param->data, sizeof(pad_mode));

        switch (pad_mode) {
        case RSA_PKCS1_PSS_PADDING: {
          new_padding = SignaturePadding::Pss;
          break;
        }
        case RSA_PKCS1_PADDING: {
          new_padding = SignaturePadding::Pkcs1;
          break;
        }
        default: {
          return false;
        }
        }

        DBGINFO("Padding now is: " << static_cast<std::int32_t>(new_padding));

        break;
      }
      case OSSL_PARAM_UTF8_STRING: {
        std::string_view pad_mode{static_cast<char*>(param->data),
                                  param->data_size};

        if (pad_mode == OSSL_PKEY_RSA_PAD_MODE_PSS) {
          new_padding = SignaturePadding::Pss;
        } else if (pad_mode == OSSL_PKEY_RSA_PAD_MODE_PKCSV15) {
          new_padding = SignaturePadding::Pkcs1;
        } else {
          return false;
        }

        DBGINFO("Padding now is: " << static_cast<std::int32_t>(new_padding));

        break;
      }
      default: {
        return false;
      }
      }
    }

    /* Get PSS padding salt length. The salt length is hardcoded with the
       signature type and hash in macOS APIs, so we only verify that OpenSSL is
       thinking to use the correct salt length. */
    param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);

    if (param != nullptr) {
      auto opt_expected_pss_salt_length =
          getExpectedPSSSaltLength(algorithm_id_);

      if (!opt_expected_pss_salt_length.has_value()) {
        return false;
      }

      switch (param->data_type) {
      case OSSL_PARAM_INTEGER: {
        std::int32_t pss_salt_length = 0;

        // In theory this should always be a ULONG, but we do some validations
        if (param->data_size <= sizeof(pss_salt_length)) {
          DBGERR("Data size not expected");
          return false;
        }

        std::memcpy(&pss_salt_length, param->data, param->data_size);

        if (pss_salt_length != *opt_expected_pss_salt_length) {
          DBGERR("Unexpected salt length");
          return false;
        }

        break;
      }
      case OSSL_PARAM_UTF8_STRING: {
        if (strcmp(static_cast<char*>(param->data),
                   OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0 ||
            strcmp(static_cast<char*>(param->data),
                   OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0 ||
            strcmp(static_cast<char*>(param->data),
                   OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0 ||
            strcmp(static_cast<char*>(param->data),
                   OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0) {
          /* Salt length is chosen by the algorithm ID anyway, and it's based on
             the digest size, so all the choices above are valid. */
          break;
        } else {
          const char* value = static_cast<char*>(param->data);
          char* end = nullptr;
          std::int32_t pss_salt_length = std::strtol(value, &end, 10);

          if (value == end) {
            DBGERR("Failed to parse salt length from string");
            return false;
          }

          if (pss_salt_length != *opt_expected_pss_salt_length) {
            DBGERR("Parsed salt length from string is not as expected");
            return false;
          }
        }
        break;
      }
      default:
        DBGERR("No saltlen parameter recognized");
        return false;
      }
    }
  }

  auto opt_algorithm_id = hashAndPaddingToSignAlgorithm(hash_ctx_, new_padding);
  if (!opt_algorithm_id.has_value()) {
    DBGERR("Could not find an algorithm id");
    return false;
  }

  algorithm_id_ = *opt_algorithm_id;
  padding_ = new_padding;

  return true;
}

SignatureCtx* SignatureCtx::clone() {
  SignatureCtx* new_ctx = new SignatureCtx();

  DBGERR("Duplicating hash ctx: " << std::hex << hash_ctx_ << " to "
                                  << new_ctx->hash_ctx_ << std::dec);
  new_ctx->provider_key_ = static_cast<ProviderKey*>(
      OsqueryKeychainKeyManagementDup(provider_key_, OSSL_KEYMGMT_SELECT_ALL));

  if (new_ctx->provider_key_ == nullptr) {
    delete new_ctx;
    return nullptr;
  }

  new_ctx->hash_ctx_ = EVP_MD_CTX_dup(hash_ctx_);

  new_ctx->algorithm_id_ = algorithm_id_;

  new_ctx->padding_ = padding_;

  return new_ctx;
}
} // namespace osquery
