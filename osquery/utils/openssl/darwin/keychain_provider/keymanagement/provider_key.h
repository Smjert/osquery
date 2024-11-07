/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>

#include <openssl/params.h>

#include <Security/SecKey.h>

namespace osquery {

enum class ProviderKeyType { Public, Private };
enum class ProviderKeyAlgorithm { RSA };

class ProviderKey {
 public:
  ProviderKey() = delete;
  ProviderKey(SecKeyRef handle,
              ProviderKeyType key_type,
              ProviderKeyAlgorithm key_algorithm);
  ~ProviderKey();

  ProviderKey(const ProviderKey& other) = delete;
  ProviderKey(ProviderKey&& other) noexcept;

  ProviderKey& operator=(const ProviderKey& other) = delete;
  ProviderKey& operator=(ProviderKey&& other) noexcept;

  ProviderKey* clone() const;

  const SecKeyRef& getHandle() const {
    return handle_;
  }
  ProviderKeyType getKeyType() const {
    return key_type_;
  }

  ProviderKeyAlgorithm getKeyAlgorithm() const {
    return key_algorithm_;
  }

  std::size_t getKeyLengthBits() const;

 private:
  SecKeyRef handle_;
  ProviderKeyType key_type_;
  ProviderKeyAlgorithm key_algorithm_;
};
} // namespace osquery
