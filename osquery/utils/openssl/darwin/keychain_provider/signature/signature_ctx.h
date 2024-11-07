/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

#include <CommonCrypto/CommonDigest.h>

#include <openssl/params.h>

#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/key_management.h>
#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/provider_key.h>

namespace osquery {

enum class SignaturePadding { None, Pss, Pkcs1 };

using HashCtx = std::variant<CC_SHA256_CTX, CC_SHA512_CTX>;

class SignatureCtx {
 public:
  SignatureCtx() = default;
  SignatureCtx(const SignatureCtx& other) = delete;
  SignatureCtx(const SignatureCtx&& other) noexcept = delete;
  SignatureCtx& operator=(const SignatureCtx& other) = delete;
  SignatureCtx& operator=(const SignatureCtx&& other) noexcept = delete;
  ~SignatureCtx();

  bool finishSignature(std::basic_string_view<std::uint8_t> hash_data,
                       std::size_t max_signature_length,
                       unsigned char* signature,
                       std::size_t& actual_signature_length);
  bool initHash(const char* digest_name, ProviderKey& key);
  [[nodiscard]] bool updateHash(const unsigned char* data, size_t data_len);
  std::size_t getSignatureLength();
  bool finishHashAndSign(unsigned char* signature,
                         std::size_t& actual_signature_length,
                         std::size_t max_signature_length);
  bool finishHashAndVerifySignature(unsigned char* signature,
                                    std::size_t signature_length);

  bool updateParams(const OSSL_PARAM params[]);

  SignatureCtx* clone();

 private:
  SecKeyAlgorithm algorithm_id_{nullptr};
  EVP_MD_CTX* hash_ctx_{};
  ProviderKey* provider_key_{nullptr};
  // NOTE: In OpenSSL, for RSA Pkcs1 is the default pad mode, so we need to set
  // it here, because OpenSSL might not call the function to set the params,
  // including the padding mode.
  SignaturePadding padding_{SignaturePadding::Pkcs1};
};
} // namespace osquery
