/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/openssl/openssl_utils.h>

#include <iomanip> // TODO: remove me
#include <iostream> // TODO: remove me

#include <sdkddkver.h>

#include <windows.h>

#include <wincrypt.h>

#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <osquery/utils/openssl/windows/cng_provider/cng.h>

namespace osquery {

namespace {
std::array<std::wstring, 2> kStores = {
    L"Root", // Trusted Root Certification Authorities
    L"CA", // Intermediate Certification Authorities
};
}

SSL_CTX* createNativeContext(
    const NativeOpenSSLParameters& openssl_parameters) {
  auto* ssl_ctx = SSL_CTX_new_ex(&openssl_parameters.getSSLLibraryContext(),
                                 "?provider=cng_provider",
                                 ::SSLv23_client_method());

  return ssl_ctx;
}

std::optional<OpenSSLProviderContext> createSystemOpenSSLProviderContext() {
  auto* lib_ctx = OSSL_LIB_CTX_new();

  if (OSSL_PROVIDER_add_builtin(
          lib_ctx, "cng_provider", OsqueryCNGProviderInit) != 1) {
    return std::nullopt;
  }

  OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(lib_ctx, "default");

  if (default_provider == nullptr) {
    return std::nullopt;
  }

  OSSL_PROVIDER* cng_provider = OSSL_PROVIDER_load(lib_ctx, "cng_provider");

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
    auto system_store = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                      X509_ASN_ENCODING,
                                      NULL,
                                      CERT_SYSTEM_STORE_LOCAL_MACHINE |
                                          CERT_STORE_READONLY_FLAG |
                                          CERT_STORE_OPEN_EXISTING_FLAG,
                                      store_name.data());

    if (system_store == 0) {
      return nullptr;
    }

    // To be used for certificate validity/expiration
    FILETIME current_time;
    GetSystemTimeAsFileTime(&current_time);

    PCCERT_CONTEXT cert_context = nullptr;

    std::vector<char> eku_buffer;
    while ((cert_context = CertEnumCertificatesInStore(
                system_store, cert_context)) != nullptr) {
      // Check that the certificate is not expired or not valid yet
      if (CertVerifyTimeValidity(&current_time, cert_context->pCertInfo) != 0) {
        continue;
      }

      WORD key_usage = 0;
      BOOL has_key_usage =
          CertGetIntendedKeyUsage(X509_ASN_ENCODING,
                                  cert_context->pCertInfo,
                                  reinterpret_cast<BYTE*>(&key_usage),
                                  sizeof(key_usage));

      /* We check that the CA has a key usage for Certificate Signing;
         if getting it didn't cause an error, the cert may be for all usages. */
      if (has_key_usage) {
        if (!(key_usage & CERT_KEY_CERT_SIGN_KEY_USAGE)) {
          continue;
        }
      } else if (GetLastError()) {
        continue;
      }

      /*
        We search the extended key usage/purpose property. If it's present,
        but there's no usage, we have to differentiate between all purposes
        being valid, and the total opposite.
        If usages are present, we want to ensure that's valid for Server Auth.
       */
      DWORD usage_size = 0;
      if (CertGetEnhancedKeyUsage(cert_context, 0, nullptr, &usage_size)) {
        if (usage_size > 0) {
          eku_buffer.resize(usage_size);
        }

        if (!CertGetEnhancedKeyUsage(
                cert_context,
                0,
                reinterpret_cast<PCERT_ENHKEY_USAGE>(eku_buffer.data()),
                &usage_size)) {
          continue;
        }

        if (eku_buffer.size() < sizeof(CERT_ENHKEY_USAGE)) {
          // Something went awry, the buffer is not big enough
          continue;
        }

        CERT_ENHKEY_USAGE usage;
        std::memcpy(&usage, eku_buffer.data(), sizeof(usage));

        // If no usage is found
        if (usage.cUsageIdentifier == 0) {
          /* And the CRYPT_E_NOT_FOUND error is NOT returned,
             then it's NOT valid for any use. Otherwise it means
             it's valid for all uses. */
          if (GetLastError() != CRYPT_E_NOT_FOUND) {
            continue;
          }
        } else {
          bool found_correct_usage = false;
          for (DWORD i = 0; i < usage.cUsageIdentifier; ++i) {
            if (strcmp(usage.rgpszUsageIdentifier[i],
                       szOID_PKIX_KP_SERVER_AUTH) == 0) {
              found_correct_usage = true;
              break;
            }
          }

          if (!found_correct_usage) {
            continue;
          }
        }
      }

      if (!search_params.organizational_unit.empty()) {
        CERT_NAME_INFO* name_info = nullptr;
        DWORD size;
        PCERT_RDN_ATTR ou_attr = nullptr;

        if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                                 reinterpret_cast<LPCSTR>(7),
                                 cert_context->pCertInfo->Subject.pbData,
                                 cert_context->pCertInfo->Subject.cbData,
                                 CRYPT_DECODE_ALLOC_FLAG,
                                 nullptr,
                                 &name_info,
                                 &size)) {
          continue;
        }

        ou_attr = CertFindRDNAttr(szOID_ORGANIZATIONAL_UNIT_NAME, name_info);

        if (ou_attr == nullptr) {
          LocalFree(name_info);
          continue;
        }

        // std::cout << "OU_TYPE: 0x" << std::setfill('0') << std::setw(2)
        //           << std::hex << ou_attr->dwValueType << std::endl;

        if (ou_attr->dwValueType != CERT_RDN_PRINTABLE_STRING) {
          continue;
        }

        // TODO: This should actually be a lowercase check and ignore
        // leading or following whitespaces
        auto cert_ou =
            std::string_view(reinterpret_cast<char*>(ou_attr->Value.pbData),
                             ou_attr->Value.cbData);

        if (cert_ou != search_params.organizational_unit) {
          LocalFree(name_info);
          continue;
        }

        LocalFree(name_info);
      }

      X509* x509 = d2i_X509(
          nullptr,
          const_cast<const unsigned char**>(&cert_context->pbCertEncoded),
          cert_context->cbCertEncoded);
      if (x509) {
        // DWORD str_type = CERT_SIMPLE_NAME_STR;
        // DWORD str_size = CertGetNameStringW(
        //     cert_context, CERT_NAME_RDN_TYPE, 0, &str_type, nullptr, 0);

        // std::wstring name_buffer(str_size, 0);
        // CertGetNameStringW(cert_context,
        //                    CERT_NAME_RDN_TYPE,
        //                    0,
        //                    &str_type,
        //                    name_buffer.data(),
        //                    static_cast<DWORD>(name_buffer.size()));

        // std::wcout << "Loading certificate: " << name_buffer << std::endl;

        int i = X509_STORE_add_cert(store, x509);

        if (i == 0) {
          return nullptr;
        }

        X509_free(x509);
      }
    }

    CertFreeCertificateContext(cert_context);
    // TODO: change flag to 0
    CertCloseStore(system_store, CERT_CLOSE_STORE_CHECK_FLAG);
  }

  if (X509_STORE_set_purpose(store, X509_PURPOSE_SSL_SERVER) == 0) {
    return nullptr;
  }

  return store;
}
} // namespace osquery
