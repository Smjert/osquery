#pragma once

#include <windows.h>

#include <wincrypt.h>

#include <optional>
#include <string>

#include <openssl/params.h>

#include <osquery/utils/openssl/windows/cng_provider/keymanagement/provider_key.h>

extern "C" const OSSL_ALGORITHM* OsqueryGetStoreAlgorithms();

namespace osquery {

class Store {
 public:
  Store() = delete;
  ~Store();

  static Store* openStore(const std::wstring& store_name);

  bool loadNextCertificate(OSSL_CALLBACK* object_cb, void* object_cbarg);
  bool loadNextPrivateKey(OSSL_CALLBACK* object_cb, void* object_cbarg);
  bool isStoreAtEof() {
    return certificates_eof_ && private_keys_eof_;
  }

  bool close();

 private:
  Store(HCERTSTORE store_handle,
        PCCERT_CONTEXT first_certificate,
        PCCERT_CONTEXT first_key_certificate,
        ProviderKey first_private_key);

  HCERTSTORE store_handle_;
  PCCERT_CONTEXT current_certificate_;
  bool certificates_eof_;

  PCCERT_CONTEXT current_key_certificate_;
  ProviderKey current_private_key_;
  bool private_keys_eof_;
};

} // namespace osquery
