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

ProviderKey::ProviderKey(NCRYPT_HANDLE handle,
                         ProviderKeyType key_type,
                         ProviderKeyAlgorithm key_algorithm)
    : handle_(handle), key_type_(key_type), key_algorithm_(key_algorithm) {}

ProviderKey::ProviderKey(ProviderKey&& other) noexcept
    : handle_(std::exchange(other.handle_, 0)),
      key_type_(other.key_type_),
      key_algorithm_(other.key_algorithm_) {}

ProviderKey& ProviderKey::operator=(ProviderKey&& other) noexcept {
  if (handle_) {
    NCryptFreeObject(handle_);
  }

  handle_ = std::exchange(other.handle_, 0);
  key_type_ = other.key_type_;
  key_algorithm_ = other.key_algorithm_;

  return *this;
}

ProviderKey::~ProviderKey() {
  if (handle_) {
    NCryptFreeObject(handle_);
  }
  handle_ = 0;
}

std::size_t ProviderKey::getKeyLengthBits() const {
  if (handle_ == 0) {
    return 0;
  }

  DWORD key_length;
  DWORD received_bytes;
  SECURITY_STATUS security_status =
      NCryptGetProperty(handle_,
                        NCRYPT_LENGTH_PROPERTY,
                        reinterpret_cast<PBYTE>(&key_length),
                        sizeof(key_length),
                        &received_bytes,
                        0);
  if (security_status != ERROR_SUCCESS ||
      received_bytes != sizeof(key_length)) {
    return 0;
  }

  return key_length;
}

ProviderKey* ProviderKey::clone() const {
  if (handle_ == 0) {
    return new ProviderKey(0, key_type_, key_algorithm_);
  }

  NCRYPT_HANDLE temp_handle = handle_;
  ProviderKey* new_key = nullptr;

  if (key_type_ == ProviderKeyType::Public) {
    DWORD public_blob_expected_size;
    SECURITY_STATUS security_status =
        NCryptExportKey(handle_,
                        0,
                        BCRYPT_RSAPUBLIC_BLOB,
                        nullptr,
                        nullptr,
                        0,
                        &public_blob_expected_size,
                        0);
    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }

    if (public_blob_expected_size < sizeof(BCRYPT_RSAKEY_BLOB)) {
      return nullptr;
    }

    DWORD public_blob_size;
    std::vector<BYTE> public_key_blob(public_blob_expected_size);

    security_status = NCryptExportKey(handle_,
                                      0,
                                      BCRYPT_RSAPUBLIC_BLOB,
                                      nullptr,
                                      public_key_blob.data(),
                                      public_blob_expected_size,
                                      &public_blob_size,
                                      0);
    if (security_status != ERROR_SUCCESS ||
        public_blob_expected_size != public_blob_size) {
      return nullptr;
    }

    NCRYPT_PROV_HANDLE prov_handle;

    security_status =
        NCryptOpenStorageProvider(&prov_handle, MS_KEY_STORAGE_PROVIDER, 0);

    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }

    new_key = new ProviderKey{0, key_type_, key_algorithm_};

    // TODO: Do we really need to clone the whole key data, or can we just get
    // another handle to it?
    // Also, does this actually clone the data, or it overwrites the previous
    // key material given that the name of the key might be the same?
    security_status =
        NCryptImportKey(prov_handle,
                        0,
                        BCRYPT_RSAPUBLIC_BLOB,
                        nullptr,
                        &new_key->handle_,
                        public_key_blob.data(),
                        static_cast<DWORD>(public_key_blob.size()),
                        0);

    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }
  } else { // Private key
    DWORD key_name_len = 0;
    DWORD key_name_expected_len = 0;
    SECURITY_STATUS security_status = NCryptGetProperty(temp_handle,
                                                        NCRYPT_NAME_PROPERTY,
                                                        nullptr,
                                                        key_name_len,
                                                        &key_name_expected_len,
                                                        0);
    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }

    std::wstring key_name(key_name_expected_len, L'\0');
    key_name_len = key_name_expected_len;
    security_status =
        NCryptGetProperty(temp_handle,
                          NCRYPT_NAME_PROPERTY,
                          reinterpret_cast<PBYTE>(key_name.data()),
                          key_name_len,
                          &key_name_expected_len,
                          0);
    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }

    DWORD key_type_flags;
    DWORD key_type_flags_expected_len = 0;

    security_status =
        NCryptGetProperty(temp_handle,
                          NCRYPT_KEY_TYPE_PROPERTY,
                          reinterpret_cast<PBYTE>(&key_type_flags),
                          sizeof(key_type_flags),
                          &key_type_flags_expected_len,
                          0);

    if (security_status != ERROR_SUCCESS ||
        sizeof(key_type_flags) != key_type_flags_expected_len) {
      return nullptr;
    }

    NCRYPT_PROV_HANDLE key_provider_handle;
    DWORD key_provider_handle_expected_len = 0;
    security_status =
        NCryptGetProperty(temp_handle,
                          NCRYPT_PROVIDER_HANDLE_PROPERTY,
                          reinterpret_cast<PBYTE>(&key_provider_handle),
                          sizeof(key_provider_handle),
                          &key_provider_handle_expected_len,
                          0);
    if (security_status != ERROR_SUCCESS ||
        sizeof(key_provider_handle) != key_provider_handle_expected_len) {
      return nullptr;
    }

    new_key = new ProviderKey{0, key_type_, key_algorithm_};

    security_status = NCryptOpenKey(key_provider_handle,
                                    &new_key->handle_,
                                    key_name.data(),
                                    0,
                                    key_type_flags);

    if (security_status != ERROR_SUCCESS) {
      return nullptr;
    }
  }

  return new_key;
}
} // namespace osquery
