/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "provider_key.h"

#include <string>
#include <utility>
#include <vector>

namespace osquery {

ProviderKey::ProviderKey(SecKeyRef handle,
                         ProviderKeyType key_type,
                         ProviderKeyAlgorithm key_algorithm)
    : handle_(handle), key_type_(key_type), key_algorithm_(key_algorithm) {}

ProviderKey::ProviderKey(ProviderKey&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)),
      key_type_(other.key_type_),
      key_algorithm_(other.key_algorithm_) {}

ProviderKey& ProviderKey::operator=(ProviderKey&& other) noexcept {
  if (handle_) {
    CFRelease(handle_);
  }

  handle_ = std::exchange(other.handle_, nullptr);
  key_type_ = other.key_type_;
  key_algorithm_ = other.key_algorithm_;

  return *this;
}

ProviderKey::~ProviderKey() {
  if (handle_) {
    CFRelease(handle_);
  }
  handle_ = nullptr;
}

std::size_t ProviderKey::getKeyLengthBits() const {
  if (handle_ == nullptr) {
    return 0;
  }

  // NOTE: This calculation is only valid for RSA keys!
  return SecKeyGetBlockSize(handle_) * 8;
}

ProviderKey* ProviderKey::clone() const {
  if (handle_ == nullptr) {
    return new ProviderKey(nullptr, key_type_, key_algorithm_);
  }

  // Increase the reference count for the clone
  CFRetain(handle_);

  return new ProviderKey(handle_, key_type_, key_algorithm_);
}
} // namespace osquery
