/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <openssl/params.h>

#include <osquery/utils/openssl/darwin/keychain_provider/keymanagement/provider_key.h>

extern "C" const OSSL_ALGORITHM* OsqueryKeychainGetStoreAlgorithms();

namespace osquery {

std::optional<const char*> storeNameToPath(std::string_view store_name);

class Store {
 public:
  Store() = delete;
  ~Store();

  static Store* openStore(std::string_view store_name);

  bool loadNextCertificate(OSSL_CALLBACK* object_cb, void* object_cbarg);
  bool loadNextPrivateKey(OSSL_CALLBACK* object_cb, void* object_cbarg);
  bool isStoreAtEof() {
    return certificates_eof_ && !current_private_key_.has_value();
  }

  bool close();

 private:
  Store(SecKeychainRef keychain,
        CFArrayRef certificates,
        std::size_t current_key_certificate_idx,
        std::optional<ProviderKey> first_private_key);
  SecKeychainRef keychain_;
  CFArrayRef certificates_;
  std::size_t current_certificate_idx_;
  bool certificates_eof_;
  std::size_t current_key_certificate_idx_;
  std::optional<ProviderKey> current_private_key_;
};

} // namespace osquery
