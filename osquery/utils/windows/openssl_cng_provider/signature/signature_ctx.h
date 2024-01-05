#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include <openssl/params.h>

#include <osquery/utils/windows/openssl_cng_provider/keymanagement/key_management.h>

namespace osquery {

enum class SignaturePadding { None, Pss, Pkcs1 };

class SignatureCtx {
 public:
  SignatureCtx() = default;
  SignatureCtx(const SignatureCtx& other) = delete;
  SignatureCtx& operator=(const SignatureCtx& other) = delete;
  ~SignatureCtx();

  bool initSignature(ProviderKey& provider_key);
  bool finishSignature(std::basic_string_view<BYTE> hash_data,
                       std::size_t max_signature_length,
                       unsigned char* signature,
                       std::size_t& actual_signature_length);
  bool initHash(const wchar_t* algorithm_id,
                BCRYPT_HASH_HANDLE hash_handle,
                ProviderKey& key);
  [[nodiscard]] bool updateHash(const unsigned char* data, size_t data_len);
  std::optional<DWORD> getSignatureLength();
  bool finishHashAndSign(unsigned char* signature,
                         std::size_t& actual_signature_length,
                         std::size_t max_signature_length);
  bool finishHashAndVerifySignature(unsigned char* signature,
                                    std::size_t signature_length);

  bool updateParams(const OSSL_PARAM params[]);

  SignatureCtx* clone();

 private:
  const wchar_t* algorithm_id_{nullptr};
  BCRYPT_HASH_HANDLE hash_handle_{nullptr};
  ProviderKey* provider_key_{nullptr};
  DWORD hash_length_{0};
  // NOTE: In OpenSSL, for RSA Pkcs1 is the default pad mode, so we need to set
  // it here, because OpenSSL might not call the function to set the params,
  // including the padding mode.
  SignaturePadding padding_{SignaturePadding::Pkcs1};
  ULONG pss_salt_length_{0};
};
} // namespace osquery
