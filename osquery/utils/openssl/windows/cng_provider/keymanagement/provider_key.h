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

#include <windows.h>

#include <ncrypt.h>

#include <openssl/params.h>

namespace osquery {

enum class ProviderKeyType { Public, Private };
enum class ProviderKeyAlgorithm { RSA };

class ProviderKey {
 public:
  ProviderKey() = delete;
  ProviderKey(NCRYPT_KEY_HANDLE handle,
              ProviderKeyType key_type,
              ProviderKeyAlgorithm key_algorithm);

  ~ProviderKey();

  ProviderKey(const ProviderKey& other) = delete;
  ProviderKey(ProviderKey&& other) noexcept;

  ProviderKey& operator=(const ProviderKey& other) = delete;
  ProviderKey& operator=(ProviderKey&& other) noexcept;

  const NCRYPT_KEY_HANDLE& getHandle() const {
    return handle_;
  }
  ProviderKeyType getKeyType() const {
    return key_type_;
  }

  ProviderKeyAlgorithm getKeyAlgorithm() const {
    return key_algorithm_;
  }

  std::size_t getKeyLengthBits() const;
  ProviderKey* clone() const;
  void freeKeyHandle();

 private:
  NCRYPT_KEY_HANDLE handle_;
  ProviderKeyType key_type_;
  ProviderKeyAlgorithm key_algorithm_;
};
} // namespace osquery
