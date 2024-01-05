/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "signature.h"

#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include <ntstatus.h>

#define WIN32_NO_STATUS
#include <windows.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <osquery/utils/openssl/windows/cng_provider/common/defines.h>
#include <osquery/utils/openssl/windows/cng_provider/common/provider_context.h>
#include <osquery/utils/openssl/windows/cng_provider/keymanagement/key_management.h>
#include <osquery/utils/openssl/windows/cng_provider/keymanagement/provider_key.h>
#include <osquery/utils/openssl/windows/cng_provider/signature/signature_ctx.h>

// #define DBGOUTPUT 1

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl
#define DBGWERR(message) std::wcerr << message << std::endl
#else
#define DBGERR(message)
#define DBGWERR(message)
#endif

extern "C" {
void* OsqueryCNGSignatureNewCtx(void* prov_ctx,
                                const char* prop_query) noexcept;
void* OsqueryCNGSignatureDupCtx(void* ctx) noexcept;
void OsqueryCNGSignatureFreeCtx(void* ctx) noexcept;
int OsqueryCNGSignatureDigestSignInit(void* ctx,
                                      const char* digest_name,
                                      void* prov_key,
                                      const OSSL_PARAM params[]) noexcept;
int OsqueryCNGSignatureDigestSignUpdate(void* ctx,
                                        const unsigned char* data,
                                        size_t data_len) noexcept;
int OsqueryCNGSignatureDigestSignFinal(void* ctx,
                                       unsigned char* sig,
                                       size_t* sig_len,
                                       size_t sig_size) noexcept;
int OsqueryCNGSignatureDigestVerifyInit(void* ctx,
                                        const char* digest_name,
                                        void* prov_key,
                                        const OSSL_PARAM params[]) noexcept;
int OsqueryCNGSignatureDigestVerifyUpdate(void* ctx,
                                          const unsigned char* data,
                                          size_t data_len) noexcept;
int OsqueryCNGSignatureDigestVerifyFinal(void* ctx,
                                         unsigned char* sig,
                                         size_t sig_len) noexcept;
int OsqueryCNGSignatureSetCtxMdParams(void* ctx,
                                      const OSSL_PARAM params[]) noexcept;
const OSSL_PARAM* OsqueryCNGSignatureSettableCtxParams(void* ctx,
                                                       void* prov_ctx) noexcept;

int OsqueryCNGSignatureSetCtxParams(void* ctx,
                                    const OSSL_PARAM params[]) noexcept;
const OSSL_PARAM* OsqueryCNGSignatureSettableCtxMdParams(
    void* ctx, void* prov_ctx) noexcept;
}

namespace osquery {
namespace {

const OSSL_DISPATCH signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureNewCtx)},
    {OSSL_FUNC_SIGNATURE_DUPCTX,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureDupCtx)},
    {OSSL_FUNC_SIGNATURE_FREECTX,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureFreeCtx)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureDigestSignInit)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureDigestSignUpdate)},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureDigestSignFinal)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureDigestVerifyInit)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
     reinterpret_cast<OSSLCNGFunctionPtr>(
         OsqueryCNGSignatureDigestVerifyUpdate)},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
     reinterpret_cast<OSSLCNGFunctionPtr>(
         OsqueryCNGSignatureDigestVerifyFinal)},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureSetCtxParams)},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(
         OsqueryCNGSignatureSettableCtxParams)},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGSignatureSetCtxMdParams)},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(
         OsqueryCNGSignatureSettableCtxMdParams)},
    {0, nullptr}};

// TODO: Use openssl hashing instead of Windows.
std::optional<const wchar_t*> OSSLDigestNameToCNG(
    const char* ossl_digest_name) {
  const EVP_MD* md = EVP_MD_fetch(nullptr, ossl_digest_name, nullptr);
  if (md == nullptr) {
    return std::nullopt;
  }

  if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_256)) {
    return BCRYPT_SHA256_ALGORITHM;
  }

  if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_384)) {
    return BCRYPT_SHA384_ALGORITHM;
  }

  if (EVP_MD_is_a(md, OSSL_DIGEST_NAME_SHA2_512)) {
    return BCRYPT_SHA512_ALGORITHM;
  }

  return std::nullopt;
}

} // namespace
} // namespace osquery

void* OsqueryCNGSignatureNewCtx(
    [[maybe_unused]] void* prov_ctx,
    [[maybe_unused]] const char* prop_query) noexcept {
  // CNGProviderCtx* provider_ctx = static_cast<CNGProviderCtx*>(prov_ctx);

  //   OsqueryCNGSignatureCtxHandle handle{
  //       provider_ctx->free_active_signature_ctxs_indices
  //           [provider_ctx->free_active_signature_ctxs_indices_head++],
  //       0};

  //   SignatureCtx* signature_ctx =
  //       &provider_ctx->active_signature_ctxs[handle.idx];
  //   ++signature_ctx->generation;
  //   handle.gen = signature_ctx->generation;

  //   void* res;
  //   std::memcpy(&res, &handle, sizeof(res));

  return new osquery::SignatureCtx();
}

void* OsqueryCNGSignatureDupCtx(void* ctx) noexcept {
  osquery::SignatureCtx* old_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  return old_ctx->clone();
}

void OsqueryCNGSignatureFreeCtx(void* ctx) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  delete sig_ctx;
}

int OsqueryCNGSignatureDigestSignInit(void* ctx,
                                      const char* digest_name,
                                      void* prov_key,
                                      const OSSL_PARAM params[]) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);
  if (sig_ctx == nullptr || digest_name == nullptr || prov_key == nullptr) {
    return 0;
  }

  auto opt_algorithm_id = osquery::OSSLDigestNameToCNG(digest_name);

  if (!opt_algorithm_id.has_value()) {
    DBGERR("No match for the hashing algorithm " << digest_name)
    return 0;
  }

  const wchar_t* algorithm_id = *opt_algorithm_id;

  BCRYPT_ALG_HANDLE alg_provider_handle = nullptr;

  /* NOTE: Passing BCRYPT_HASH_REUSABLE_FLAG as the last parameter can make the
     hash object reusable after having called BcryptFinishHash. This might be
     useful if there are performance issues. */
  auto status = BCryptOpenAlgorithmProvider(
      &alg_provider_handle, algorithm_id, nullptr, 0);

  if (status != STATUS_SUCCESS) {
    return 0;
  }

  BCRYPT_HASH_HANDLE hash_handle = nullptr;
  status = BCryptCreateHash(
      alg_provider_handle, &hash_handle, nullptr, 0, nullptr, 0, 0);

  if (status != STATUS_SUCCESS) {
    DBGERR("Failed to create a hash");
    return 0;
  }

  BCryptCloseAlgorithmProvider(&alg_provider_handle, 0);

  return status == STATUS_SUCCESS &&
         sig_ctx->initHash(algorithm_id,
                           hash_handle,
                           *static_cast<osquery::ProviderKey*>(prov_key)) &&
         sig_ctx->updateParams(params);
}

int OsqueryCNGSignatureDigestSignUpdate(void* ctx,
                                        const unsigned char* data,
                                        size_t data_len) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || data == nullptr) {
    return 0;
  }

  return sig_ctx->updateHash(data, data_len);
}

int OsqueryCNGSignatureDigestSignFinal(void* ctx,
                                       unsigned char* sig,
                                       size_t* sig_len,
                                       size_t sig_size) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || sig_len == nullptr) {
    return 0;
  }

  if (sig == nullptr) {
    auto opt_length = sig_ctx->getSignatureLength();

    if (!opt_length.has_value()) {
      return 0;
    }

    *sig_len = *opt_length;

    return 1;
  }

  return sig_ctx->finishHashAndSign(sig, *sig_len, sig_size);
}

int OsqueryCNGSignatureDigestVerifyInit(void* ctx,
                                        const char* digest_name,
                                        void* prov_key,
                                        const OSSL_PARAM params[]) noexcept {
  return OsqueryCNGSignatureDigestSignInit(ctx, digest_name, prov_key, params);
}

int OsqueryCNGSignatureDigestVerifyUpdate(void* ctx,
                                          const unsigned char* data,
                                          size_t data_len) noexcept {
  return OsqueryCNGSignatureDigestSignUpdate(ctx, data, data_len);
}
int OsqueryCNGSignatureDigestVerifyFinal(void* ctx,
                                         unsigned char* sig,
                                         size_t sig_len) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr || sig == nullptr || sig_len == 0) {
    return 0;
  }

  return sig_ctx->finishHashAndVerifySignature(sig, sig_len);
}

int OsqueryCNGSignatureSetCtxParams(void* ctx,
                                    const OSSL_PARAM params[]) noexcept {
  osquery::SignatureCtx* sig_ctx = static_cast<osquery::SignatureCtx*>(ctx);

  if (sig_ctx == nullptr) {
    return 0;
  }

  return sig_ctx->updateParams(params);
}

const OSSL_PARAM* OsqueryCNGSignatureSettableCtxParams(
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

int OsqueryCNGSignatureSetCtxMdParams(void* ctx,
                                      const OSSL_PARAM params[]) noexcept {
  return OsqueryCNGSignatureSetCtxParams(ctx, params);
}

const OSSL_PARAM* OsqueryCNGSignatureSettableCtxMdParams(
    void* ctx, void* prov_ctx) noexcept {
  return OsqueryCNGSignatureSettableCtxParams(ctx, prov_ctx);
}

const OSSL_ALGORITHM* OsqueryGetSignatureAlgorithms() {
  static const OSSL_ALGORITHM signature[] = {
      {"RSA:rsaEncryption",
       osquery::algorithm_properties,
       osquery::signature_functions,
       "RSA signature implementation backed by Windows CNG"},
      /* Other algorithm names include (but are not limited to) ED25519, ED448,
         EC:id-ecPublicKey, DSA, X25519 */
      {nullptr, nullptr, nullptr}};

  return signature;
}

namespace osquery {
SignatureCtx::~SignatureCtx() {
  BCryptDestroyHash(hash_handle_);
  hash_handle_ = nullptr;
  provider_key_ = nullptr;
}

bool SignatureCtx::initHash(const wchar_t* algorithm_id,
                            BCRYPT_HASH_HANDLE hash_handle,
                            ProviderKey& key) {
  DBGERR("Initializing hash handle: " << std::hex << hash_handle << " and key: "
                                      << key.getHandle() << std::dec);

  algorithm_id_ = algorithm_id;
  hash_handle_ = hash_handle;
  provider_key_ = &key;

  ULONG pcb_result;

  NTSTATUS status = BCryptGetProperty(hash_handle_,
                                      BCRYPT_HASH_LENGTH,
                                      reinterpret_cast<PUCHAR>(&hash_length_),
                                      sizeof(hash_length_),
                                      &pcb_result,
                                      0);

  if (status != STATUS_SUCCESS) {
    return false;
  }

  DBGERR("Hash length: " << std::hex << hash_length_ << std::dec);

  return true;
}

bool SignatureCtx::updateHash(const unsigned char* data, size_t data_len) {
  DBGERR("Updating hash handle: " << std::hex << hash_handle_ << std::dec);

  // NOTE: The const_cast here is safe because the function is not going to
  // modify the input
  NTSTATUS status = BCryptHashData(
      hash_handle_, const_cast<PUCHAR>(data), static_cast<ULONG>(data_len), 0);

  if (status != STATUS_SUCCESS) {
    DBGERR("Failed to update hash");
  }

  return status == STATUS_SUCCESS;
}

std::optional<DWORD> SignatureCtx::getSignatureLength() {
  // TODO: maybe the calculation here can be actually cached when we init the
  // hash, and only update it if something else changes?

  std::vector<char> dummyHash(hash_length_);
  DWORD signature_length = 0;

  // NOTE: For RSA the padding doesn't affect the length of the sign, so we
  // don't need to pass any padding information
  SECURITY_STATUS sign_result =
      NCryptSignHash(provider_key_->getHandle(),
                     nullptr,
                     reinterpret_cast<PBYTE>(dummyHash.data()),
                     static_cast<DWORD>(dummyHash.size()),
                     nullptr,
                     0,
                     &signature_length,
                     0);

  if (sign_result != ERROR_SUCCESS) {
    return std::nullopt;
  }

  return signature_length;
}

bool SignatureCtx::finishSignature(std::basic_string_view<BYTE> hash_data,
                                   std::size_t max_signature_length,
                                   unsigned char* signature,
                                   std::size_t& actual_signature_length) {
  SECURITY_STATUS sign_result = ERROR_INVALID_HANDLE;
  DWORD signature_length = 0;

  switch (padding_) {
  case SignaturePadding::Pss: {
    DBGERR("Finishing signature with PSS padding");
    BCRYPT_PSS_PADDING_INFO padding_info{algorithm_id_, pss_salt_length_};

    sign_result = NCryptSignHash(provider_key_->getHandle(),
                                 &padding_info,
                                 const_cast<PBYTE>(hash_data.data()),
                                 static_cast<DWORD>(hash_data.size()),
                                 signature,
                                 static_cast<DWORD>(max_signature_length),
                                 &signature_length,
                                 BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG);

    break;
  }
  case SignaturePadding::Pkcs1: {
    DBGERR("Finishing signature with PKCS1 padding");
    BCRYPT_PKCS1_PADDING_INFO padding_info{algorithm_id_};

    sign_result = NCryptSignHash(provider_key_->getHandle(),
                                 &padding_info,
                                 const_cast<PBYTE>(hash_data.data()),
                                 static_cast<DWORD>(hash_data.size()),
                                 signature,
                                 static_cast<DWORD>(max_signature_length),
                                 &signature_length,
                                 BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG);
    break;
  }
  case SignaturePadding::None: {
    return false;
  }
  }

  if (sign_result != ERROR_SUCCESS) {
    DBGERR("Failed to sign");
    return false;
  }

  DBGERR("Successfully signed hash");

  std::stringstream ss;

  for (auto b : hash_data) {
    ss << std::setw(2) << std::setfill('0') << std::hex
       << (static_cast<std::uint32_t>(b) & 0xFF);
  }

  DBGERR(ss);

  actual_signature_length = signature_length;

  return true;
}

bool SignatureCtx::finishHashAndSign(unsigned char* signature,
                                     std::size_t& actual_signature_length,
                                     std::size_t max_signature_length) {
  std::vector<UCHAR> hash_data(hash_length_);

  DBGERR("Finish Hash Signature with handle: " << std::hex << hash_handle_
                                               << std::dec);

  NTSTATUS status = BCryptFinishHash(
      hash_handle_, hash_data.data(), static_cast<ULONG>(hash_data.size()), 0);

  if (status != STATUS_SUCCESS) {
    DBGERR("Failed to finish hash with error: " << std::hex << status
                                                << std::dec);
    return false;
  }

  return finishSignature(
      std::basic_string_view<BYTE>(hash_data.data(), hash_data.size()),
      max_signature_length,
      signature,
      actual_signature_length);
}

bool SignatureCtx::finishHashAndVerifySignature(unsigned char* signature,
                                                std::size_t signature_length) {
  std::vector<UCHAR> hash_data(hash_length_);

  DBGERR("Finish Hash to verify with handle: " << std::hex << hash_handle_
                                               << std::dec);

  NTSTATUS status = BCryptFinishHash(
      hash_handle_, hash_data.data(), static_cast<ULONG>(hash_data.size()), 0);

  if (status != STATUS_SUCCESS) {
    DBGERR("Failed to finish hash to verify with error: " << std::hex << status
                                                          << std::dec);
    return false;
  }

  SECURITY_STATUS sign_result = ERROR_INVALID_HANDLE;
  switch (padding_) {
  case SignaturePadding::Pss: {
    BCRYPT_PSS_PADDING_INFO padding_info{algorithm_id_, pss_salt_length_};

    sign_result =
        NCryptVerifySignature(provider_key_->getHandle(),
                              &padding_info,
                              reinterpret_cast<PBYTE>(hash_data.data()),
                              static_cast<DWORD>(hash_data.size()),
                              signature,
                              static_cast<DWORD>(signature_length),
                              BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG);

    break;
  }
  case SignaturePadding::Pkcs1: {
    BCRYPT_PKCS1_PADDING_INFO padding_info{algorithm_id_};

    sign_result =
        NCryptVerifySignature(provider_key_->getHandle(),
                              &padding_info,
                              reinterpret_cast<PBYTE>(hash_data.data()),
                              static_cast<DWORD>(hash_data.size()),
                              signature,
                              static_cast<DWORD>(signature_length),
                              BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG);
    break;
  }
  case SignaturePadding::None: {
    return false;
  }
  }

  if (sign_result != ERROR_SUCCESS) {
    DBGERR("Signature verification failed: " << std::hex << sign_result
                                             << std::dec);
    return false;
  }

  return true;
}

bool SignatureCtx::updateParams(const OSSL_PARAM params[]) {
  bool parameter_found = false;

  if (params == nullptr) {
    return true;
  }

  // Get pad mode parameter
  const OSSL_PARAM* param =
      OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);

  // TODO: avoid the signature params to be half set.
  if (param != nullptr) {
    parameter_found = true;

    switch (param->data_type) {
    case OSSL_PARAM_INTEGER: {
      int pad_mode = 0;

      if (param->data_size != sizeof(pad_mode)) {
        return false;
      }

      std::memcpy(&pad_mode, param->data, sizeof(pad_mode));

      switch (pad_mode) {
      case RSA_PKCS1_PSS_PADDING: {
        padding_ = SignaturePadding::Pss;
        break;
      }
      case RSA_PKCS1_PADDING: {
        padding_ = SignaturePadding::Pkcs1;
        break;
      }
      default: {
        return false;
      }
      }

      break;
    }
    case OSSL_PARAM_UTF8_STRING: {
      std::string_view pad_mode{static_cast<char*>(param->data),
                                param->data_size};

      if (pad_mode == OSSL_PKEY_RSA_PAD_MODE_PSS) {
        padding_ = SignaturePadding::Pss;
      } else if (pad_mode == OSSL_PKEY_RSA_PAD_MODE_PKCSV15) {
        padding_ = SignaturePadding::Pkcs1;
      } else {
        return false;
      }

      break;
    }
    default: {
      return false;
    }
    }
  }

  // TODO: Ensure salt is always as long as the hash in input
  // Get PSS padding salt length
  param = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);

  if (param != nullptr) {
    parameter_found = true;

    switch (param->data_type) {
    case OSSL_PARAM_INTEGER: {
      // In theory this should always be a ULONG, but we do some validations
      if (param->data_size <= sizeof(pss_salt_length_)) {
        return false;
      }

      pss_salt_length_ = 0;
      std::memcpy(&pss_salt_length_, param->data, param->data_size);
      break;
    }
    case OSSL_PARAM_UTF8_STRING: {
      if (strcmp(static_cast<char*>(param->data),
                 OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0) {
        ULONG received_bytes;
        auto status =
            BCryptGetProperty(hash_handle_,
                              BCRYPT_HASH_LENGTH,
                              reinterpret_cast<PUCHAR>(&pss_salt_length_),
                              sizeof(pss_salt_length_),
                              &received_bytes,
                              0);
        if (status != STATUS_SUCCESS || received_bytes == 0) {
          pss_salt_length_ = 0;
          return 0;
        }
      } else if (strcmp(static_cast<char*>(param->data),
                        OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0) {
        auto key_length = provider_key_->getKeyLengthBits();
        if (key_length == 0) {
          return false;
        }

        // TODO: calculate saltlength based on the key length
      }
      return false;
    }
    default:
      return false;
    }
  }

  if (!parameter_found) {
    return false;
  }

  return true;
}

SignatureCtx* SignatureCtx::clone() {
  SignatureCtx* new_ctx = new SignatureCtx();

  NTSTATUS status =
      BCryptDuplicateHash(hash_handle_, &new_ctx->hash_handle_, nullptr, 0, 0);

  if (status != STATUS_SUCCESS) {
    return nullptr;
  }

  DBGERR("Duplicating hash handle: " << std::hex << hash_handle_ << " to "
                                     << new_ctx->hash_handle_ << std::dec);

  new_ctx->algorithm_id_ = algorithm_id_;

  new_ctx->provider_key_ = static_cast<ProviderKey*>(
      OsqueryCNGKeyManagementDup(provider_key_, OSSL_KEYMGMT_SELECT_ALL));

  if (new_ctx->provider_key_ == nullptr) {
    return nullptr;
  }

  new_ctx->padding_ = padding_;
  new_ctx->pss_salt_length_ = pss_salt_length_;
  new_ctx->hash_length_ = hash_length_;

  return new_ctx;
}
} // namespace osquery
