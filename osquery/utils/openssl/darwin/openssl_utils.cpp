/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <array>
#include <string>
// TODO: remove me
#include <iostream>

#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <Security/Security.h>

#include <osquery/utils/openssl/darwin/keychain_provider/keychain.h>
#include <osquery/utils/openssl/darwin/keychain_provider/store/store.h>
#include <osquery/utils/openssl/openssl_utils.h>

#define DBGOUTPUT 1

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl;
#define DBGWERR(message) std::wcerr << message << std::endl;
#define DBGINFO(message) std::cout << message << std::endl;
#else
#define DBGERR(message)
#define DBGWERR(message)
#define DBGINFO(message)
#endif

namespace osquery {

namespace {
std::array<std::string, 2> kStores = {
    "System",
    "SystemRoot",
};
}

SSL_CTX* createNativeContext(
    const NativeOpenSSLParameters& openssl_parameters) {
  auto* ssl_ctx = SSL_CTX_new_ex(&openssl_parameters.getSSLLibraryContext(),
                                 "?provider=keychain_provider",
                                 ::SSLv23_client_method());

  return ssl_ctx;
}

std::optional<OpenSSLProviderContext> createSystemOpenSSLProviderContext() {
  auto* lib_ctx = OSSL_LIB_CTX_new();

  if (OSSL_PROVIDER_add_builtin(
          lib_ctx, "keychain_provider", OsqueryKeychainProviderInit) != 1) {
    return std::nullopt;
  }

  OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(lib_ctx, "default");

  if (default_provider == nullptr) {
    return std::nullopt;
  }

  OSSL_PROVIDER* cng_provider =
      OSSL_PROVIDER_load(lib_ctx, "keychain_provider");

  if (cng_provider == nullptr) {
    return std::nullopt;
  }

  OpenSSLProviderContext provider_context(
      *lib_ctx, *default_provider, *cng_provider);

  return provider_context;
}

X509_STORE* getCABundleFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateFields& search_params) {
  X509_STORE* store = X509_STORE_new();
  for (const auto& store_name : kStores) {
    auto opt_keychain_path = storeNameToPath(store_name);

    if (!opt_keychain_path.has_value()) {
      return nullptr;
    }

    SecKeychainRef keychain;
    auto result = SecKeychainOpen(*opt_keychain_path, &keychain);

    if (result != errSecSuccess || keychain == nullptr) {
      return nullptr;
    }

    const void* keychains_values[] = {keychain};
    auto keychains = CFArrayCreate(
        kCFAllocatorDefault, keychains_values, 1, &kCFTypeArrayCallBacks);

    if (keychains == nullptr) {
      return nullptr;
    }

    const void* keys[] = {
        kSecClass, kSecReturnRef, kSecMatchLimit, kSecMatchSearchList};
    const void* values[] = {
        kSecClassCertificate, kCFBooleanTrue, kSecMatchLimitAll, keychains};
    CFDictionaryRef query =
        CFDictionaryCreate(kCFAllocatorDefault,
                           keys,
                           values,
                           sizeof(keys) / sizeof(void*),
                           &kCFCopyStringDictionaryKeyCallBacks,
                           &kCFTypeDictionaryValueCallBacks);

    if (query == nullptr) {
      DBGERR("Failed to initialize the certificates query");
      return nullptr;
    }

    CFArrayRef certificates = nullptr;
    OSStatus os_status =
        SecItemCopyMatching(query, reinterpret_cast<CFTypeRef*>(&certificates));
    if (os_status != noErr) {
      DBGERR("Failed to find certificates in store: "
             << store_name << ", error: " << os_status);
      return nullptr;
    }

    auto certificates_count = CFArrayGetCount(certificates);

    const void* certificate_attributes_keys[]{kSecOIDX509V1SubjectName,
                                              kSecOIDX509V1ValidityNotAfter,
                                              kSecOIDX509V1ValidityNotBefore,
                                              kSecOIDKeyUsage,
                                              kSecOIDExtendedKeyUsage};

    std::vector<
        std::pair<CFStringRef, std::reference_wrapper<const std::string>>>
        params;
    if (!search_params.common_name.empty()) {
      params.push_back(std::make_pair(kSecOIDCommonName,
                                      std::cref(search_params.common_name)));
    }

    if (!search_params.organizational_unit.empty()) {
      params.push_back(
          std::make_pair(kSecOIDOrganizationalUnitName,
                         std::cref(search_params.organizational_unit)));
    }

    for (std::int32_t i = 0; i < certificates_count; ++i) {
      auto certificate =
          (SecCertificateRef)CFArrayGetValueAtIndex(certificates, i);
      auto cert_attr_key_array =
          CFArrayCreate(nullptr,
                        certificate_attributes_keys,
                        sizeof(certificate_attributes_keys) / sizeof(void*),
                        &kCFTypeArrayCallBacks);

      CFErrorRef error = nullptr;
      auto certificate_attributes =
          SecCertificateCopyValues(certificate, cert_attr_key_array, &error);

      CFRelease(cert_attr_key_array);

      if (certificate_attributes == nullptr) {
        continue;
      }

      if (error != nullptr) {
        std::cout << "Error code: " << CFErrorGetCode(error) << std::endl;
      }

      CFDictionaryRef not_before_attribute =
          (CFDictionaryRef)CFDictionaryGetValue(certificate_attributes,
                                                kSecOIDX509V1ValidityNotBefore);

      if (not_before_attribute == nullptr) {
        std::cerr << "No not before attribute" << std::endl;
        continue;
      }

      CFDictionaryRef not_after_attribute =
          (CFDictionaryRef)CFDictionaryGetValue(certificate_attributes,
                                                kSecOIDX509V1ValidityNotAfter);

      if (not_after_attribute == nullptr) {
        std::cerr << "No not after attribute" << std::endl;
        continue;
      }

      auto not_before_time_number = (CFNumberRef)CFDictionaryGetValue(
          not_before_attribute, kSecPropertyKeyValue);

      double not_before_time = 0;
      CFNumberGetValue(not_before_time_number,
                       CFNumberType::kCFNumberFloat64Type,
                       &not_before_time);

      // describe255(not_before_date);

      auto now = CFAbsoluteTimeGetCurrent();
      if (now < not_before_time) {
        continue;
      }

      auto not_after_time_number = (CFNumberRef)CFDictionaryGetValue(
          not_after_attribute, kSecPropertyKeyValue);

      double not_after_time = 0;
      CFNumberGetValue(not_after_time_number,
                       CFNumberType::kCFNumberFloat64Type,
                       &not_after_time);

      if (now > not_after_time) {
        continue;
      }

      CFStringRef certificate_desc = SecCertificateCopyLongDescription(
          kCFAllocatorDefault, certificate, nullptr);

      CFShow(certificate_desc);

      auto key_usage = (CFDictionaryRef)CFDictionaryGetValue(
          certificate_attributes, kSecOIDKeyUsage);

      if (key_usage != nullptr) {
        auto key_usage_number =
            (CFNumberRef)CFDictionaryGetValue(key_usage, kSecPropertyKeyValue);

        if (key_usage_number == nullptr) {
          continue;
        }

        CFShow(key_usage_number);

        std::int32_t key_usage_value = 0;
        if (!CFNumberGetValue(key_usage_number,
                              CFNumberType::kCFNumberIntType,
                              &key_usage_value)) {
          continue;
        }

        // Bit for Key Cert Sign
        if (key_usage_value > 0 && (key_usage_value & 0x20) != 0x20) {
          std::cout << "Incorrect key usage purpose" << std::endl;
          continue;
        }
      }

      auto extended_key_usage_attribute = (CFDictionaryRef)CFDictionaryGetValue(
          certificate_attributes, kSecOIDExtendedKeyUsage);

      if (extended_key_usage_attribute != nullptr) {
        auto extended_key_usage_array = (CFArrayRef)CFDictionaryGetValue(
            extended_key_usage_attribute, kSecPropertyKeyValue);

        if (extended_key_usage_array == nullptr) {
          continue;
        }

        // describe255(extended_key_usage_array);

        if (CFGetTypeID(extended_key_usage_array) != CFArrayGetTypeID()) {
          std::cerr << "Not an array!" << std::endl;
        }

        bool has_correct_purpose = false;
        for (CFIndex i = 0; i < CFArrayGetCount(extended_key_usage_array);
             ++i) {
          auto extended_key_usage_value =
              (CFDataRef)CFArrayGetValueAtIndex(extended_key_usage_array, i);

          const char oid_server_auth_bytes[] = {
              0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
          const char oid_any_usage_bytes[] = {0x55, 0x1D, 0x25, 0x00};

          auto eku_data = CFDataGetBytePtr(extended_key_usage_value);
          auto eku_data_length = CFDataGetLength(extended_key_usage_value);

          for (std::size_t i = 0; i < eku_data_length; ++i) {
            std::cout << std::hex << (static_cast<int>(eku_data[i]) & 0xFF)
                      << std::setw(2) << std::setfill('0');
          }
          std::cout << std::endl;

          if (eku_data_length != sizeof(oid_server_auth_bytes) &&
              eku_data_length != sizeof(oid_any_usage_bytes)) {
            continue;
          }

          if (std::equal(oid_server_auth_bytes,
                         oid_server_auth_bytes + sizeof(oid_server_auth_bytes),
                         eku_data,
                         eku_data + eku_data_length)) {
            has_correct_purpose = true;
            break;
          }

          if (std::equal(oid_any_usage_bytes,
                         oid_any_usage_bytes + sizeof(oid_any_usage_bytes),
                         eku_data,
                         eku_data + eku_data_length)) {
            has_correct_purpose = true;
            break;
          }

          // describe255(extended_key_usage_value);

          // if (CFStringCompare(extended_key_usage_value, kSecOIDServerAuth, 0)
          // ==
          //     kCFCompareEqualTo) {
          //   has_correct_purpose = true;
          //   break;
          // }

          // if (CFStringCompare(extended_key_usage_value,
          //                     kSecOIDExtendedKeyUsageAny,
          //                     0) == kCFCompareEqualTo) {
          //   has_correct_purpose = true;
          //   break;
          // }
        }

        if (!has_correct_purpose) {
          continue;
        }
      }

      // std::vector<const void*>
      // keys(CFDictionaryGetCount(subject_attributes)); std::vector<const
      // void*> values(
      //     CFDictionaryGetCount(subject_attributes));

      // CFDictionaryGetKeysAndValues(
      //     subject_attributes, keys.data(), values.data());

      // for (const auto key : keys) {
      //   CFTypeID key_id = CFGetTypeID(key);

      //   std::cout << "Key type: " << key_id << std::endl;

      //   if (key_id == CFStringGetTypeID()) {
      //     const CFStringRef key_str = (const CFStringRef)key;
      //     auto utf16_length = CFStringGetLength(key_str);
      //     auto length = CFStringGetMaximumSizeForEncoding(
      //         utf16_length, kCFStringEncodingUTF8);

      //     if (length == kCFNotFound) {
      //       std::cerr << "Failed to get string length" << std::endl;
      //       continue;
      //     }

      //     std::string key_c_str(length, '\0');

      //     CFStringGetCString(key_str,
      //                        key_c_str.data(),
      //                        key_c_str.size(),
      //                        kCFStringEncodingUTF8);

      //     std::cout << "Key: " << key_c_str << std::endl;
      //   }
      // }

      if (!params.empty()) {
        CFDictionaryRef subject_attributes =
            (CFDictionaryRef)CFDictionaryGetValue(certificate_attributes,
                                                  kSecOIDX509V1SubjectName);

        CFArrayRef subject_values = (CFArrayRef)CFDictionaryGetValue(
            subject_attributes, kSecPropertyKeyValue);

        if (subject_values == nullptr) {
          continue;
        }

        std::size_t attributesFound = 0;
        for (CFIndex i = 0; i < CFArrayGetCount(subject_values); i++) {
          CFDictionaryRef element =
              (CFDictionaryRef)CFArrayGetValueAtIndex(subject_values, i);
          CFStringRef label =
              (CFStringRef)CFDictionaryGetValue(element, kSecPropertyKeyLabel);

          if (label == nullptr) {
            continue;
          }

          for (const auto& param : params) {
            std::cout << "CA label: ";
            CFShow(label);
            if (CFStringCompare(label, param.first, 0) == kCFCompareEqualTo) {
              CFStringRef value = (CFStringRef)CFDictionaryGetValue(
                  element, kSecPropertyKeyValue);

              if (value == nullptr) {
                break;
              }

              CFStringRef expected_value =
                  CFStringCreateWithCStringNoCopy(kCFAllocatorDefault,
                                                  param.second.get().c_str(),
                                                  kCFStringEncodingUTF8,
                                                  kCFAllocatorNull);
              if (expected_value == nullptr) {
                break;
              }

              std::cout << "CA: ";
              CFShow(value);

              if (CFStringCompare(value, expected_value, 0) ==
                  kCFCompareEqualTo) {
                ++attributesFound;
              }

              if (attributesFound == params.size()) {
                break;
              }
            }
          }
        }

        if (attributesFound != params.size()) {
          continue;
        }
      }

      CFDataRef certificate_data = SecCertificateCopyData(certificate);

      const std::uint8_t* certificate_data_buffer =
          CFDataGetBytePtr(certificate_data);
      std::size_t certificate_data_length = CFDataGetLength(certificate_data);
      X509* x509_cert =
          d2i_X509(nullptr, &certificate_data_buffer, certificate_data_length);

      CFRelease(certificate_data);

      if (x509_cert) {
        auto name = X509_get_issuer_name(x509_cert);

        char name_buffer[1024];
        X509_NAME_oneline(name, name_buffer, sizeof(name_buffer));

        std::cout << "Issuer name: " << name_buffer << std::endl;

        auto res = X509_STORE_add_cert(store, x509_cert);

        if (res == 0) {
          std::cout << "Failed to add a certificate!" << std::endl;
          return nullptr;
        }

        X509_free(x509_cert);
      }
    }
  }

  if (X509_STORE_set_purpose(store, X509_PURPOSE_SSL_SERVER) == 0) {
    return nullptr;
  }

  return store;
}

} // namespace osquery
