#include <osquery/utils/openssl/openssl_utils.h>

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

std::optional<std::pair<X509*, EVP_PKEY*>> getClientCertificateFromHash(
    OSSL_STORE_CTX& store_ctx,
    const NativeOpenSSLParameters::CertificateHash& cert_hash) {
  X509* client_cert = nullptr;
  EVP_PKEY* private_key = nullptr;

  while (!OSSL_STORE_eof(&store_ctx)) {
    auto* store_info = OSSL_STORE_load(&store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (client_cert == nullptr &&
        OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* cert = OSSL_STORE_INFO_get1_CERT(store_info);

      if (cert != nullptr) {
        const EVP_MD* cert_digest = EVP_sha1();
        const auto hash_size = EVP_MD_get_size(cert_digest);
        std::vector<std::uint8_t> hash(hash_size);

        if (X509_digest(cert, cert_digest, hash.data(), nullptr) == 0) {
          return std::nullopt;
        }

        if (std::equal(cert_hash.hash.begin(),
                       cert_hash.hash.end(),
                       hash.begin(),
                       hash.end())) {
          client_cert = cert;
        }
      }
    } else if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
      if (client_cert == nullptr) {
        return std::nullopt;
      }

      auto* found_private_key = OSSL_STORE_INFO_get1_PKEY(store_info);

      // Verify that this is the private key of the selected certificate
      if (X509_check_private_key(client_cert, found_private_key)) {
        private_key = found_private_key;
        break;
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }

  if (private_key == nullptr) {
    return std::nullopt;
  }

  return std::make_pair(client_cert, private_key);
}

std::optional<std::pair<X509*, EVP_PKEY*>> getClientCertificateFromFields(
    OSSL_STORE_CTX& store_ctx,
    const NativeOpenSSLParameters::CertificateFields& cert_fields) {
  X509* client_cert = nullptr;
  EVP_PKEY* private_key = nullptr;

  time_t current_time = time(nullptr);

  while (!OSSL_STORE_eof(&store_ctx)) {
    auto* store_info = OSSL_STORE_load(&store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (client_cert == nullptr &&
        OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* cert = OSSL_STORE_INFO_get1_CERT(store_info);

      if (cert != nullptr) {
        const ASN1_TIME* cert_not_after = X509_get0_notAfter(cert);

        // On error, or on the certificate date being expired, we skip
        if (X509_cmp_time(cert_not_after, &current_time) != 1) {
          continue;
        }

        const ASN1_TIME* cert_not_before = X509_get0_notBefore(cert);

        // On error, or on the certificate not being yet usable, we skip
        if (X509_cmp_time(cert_not_before, &current_time) != -1) {
          continue;
        }

        auto ex_flags = X509_get_extension_flags(cert);

        if (ex_flags & EXFLAG_INVALID_POLICY || ex_flags & EXFLAG_CRITICAL) {
          continue;
        }

        // If we have a key usage, let's ensure that we have at least Digital
        // Signature
        if (ex_flags & EXFLAG_KUSAGE) {
          auto key_usage_flags = X509_get_key_usage(cert);

          if (!(key_usage_flags & KU_DIGITAL_SIGNATURE)) {
            continue;
          }
        }

        /* If we have an extended key usage, let's ensure that we have at least
          TLS Client Web Authentication */
        if (ex_flags & EXFLAG_XKUSAGE) {
          auto ex_key_flags = X509_get_extended_key_usage(cert);

          if (!(ex_key_flags & XKU_SSL_CLIENT)) {
            continue;
          }
        }

        /* If we have no KU or EKU, it's an all purpose cert,
           which we still accept */

        // Now filter the cert by CN and OU
        X509_NAME* subject_name = X509_get_subject_name(cert);

        bool certificate_found = false;

        if (!cert_fields.common_name.empty()) {
          /* NOTE: Per RFC 5280 the Common Name should be max 64 characters;
            here we add the null terminator too. */
          std::array<char, 65> cert_common_name;
          std::uint32_t buffer_length =
              static_cast<std::uint32_t>(cert_common_name.size());
          if (X509_NAME_get_text_by_NID(subject_name,
                                        NID_commonName,
                                        cert_common_name.data(),
                                        buffer_length)) {
            if (cert_fields.common_name == cert_common_name.data()) {
              certificate_found = true;
            }
          }
        }

        if (!cert_fields.organizational_unit.empty()) {
          certificate_found = false;
          std::array<char, 65> cert_organization_unit;
          std::uint32_t buffer_length =
              static_cast<std::uint32_t>(cert_organization_unit.size());
          if (X509_NAME_get_text_by_NID(subject_name,
                                        NID_organizationalUnitName,
                                        cert_organization_unit.data(),
                                        buffer_length)) {
            if (std::equal(cert_fields.organizational_unit.begin(),
                           cert_fields.organizational_unit.end(),
                           cert_organization_unit.begin(),
                           cert_organization_unit.begin() + buffer_length)) {
              certificate_found = true;
            }
          }
        }

        if (certificate_found) {
          client_cert = cert;
        }
      }
    } else if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
      if (client_cert == nullptr) {
        return std::nullopt;
      }

      auto* found_private_key = OSSL_STORE_INFO_get1_PKEY(store_info);

      // Verify that this is the private key of the selected certificate
      if (X509_check_private_key(client_cert, found_private_key)) {
        private_key = found_private_key;
        break;
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }

  if (private_key == nullptr) {
    return std::nullopt;
  }

  return std::make_pair(client_cert, private_key);
}
} // namespace

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

std::optional<std::pair<X509*, EVP_PKEY*>>
getClientCertificateFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateSearchParameters& search_params) {
  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("cng://MY",
                                                      &lib_ctx,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  if (ossl_store_ctx == nullptr) {
    return std::nullopt;
  }

  using CertificateCompare = bool (*)(
      const X509*, const NativeOpenSSLParameters::CertificateSearchParameters&);

  std::optional<std::pair<X509*, EVP_PKEY*>> opt_client_cert_data;

  if (std::holds_alternative<NativeOpenSSLParameters::CertificateHash>(
          search_params)) {
    opt_client_cert_data = getClientCertificateFromHash(
        *ossl_store_ctx,
        std::get<NativeOpenSSLParameters::CertificateHash>(search_params));

  } else {
    opt_client_cert_data = getClientCertificateFromFields(
        *ossl_store_ctx,
        std::get<NativeOpenSSLParameters::CertificateFields>(search_params));
  }

  OSSL_STORE_close(ossl_store_ctx);

  return opt_client_cert_data;
}

X509_STORE* getCABundleFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateFields& search_params) {
  X509_STORE* store = X509_STORE_new();
  for (const auto& store_name : kStores) {
    auto hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
                                X509_ASN_ENCODING,
                                NULL,
                                CERT_SYSTEM_STORE_LOCAL_MACHINE |
                                    CERT_STORE_READONLY_FLAG |
                                    CERT_STORE_OPEN_EXISTING_FLAG,
                                store_name.data());

    if (hStore == 0) {
      return nullptr;
    }

    PCCERT_CONTEXT pContext = nullptr;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) !=
           nullptr) {
      DWORD key_usage = 0;
      BOOL has_key_usage =
          CertGetIntendedKeyUsage(X509_ASN_ENCODING,
                                  pContext->pCertInfo,
                                  reinterpret_cast<BYTE*>(&key_usage),
                                  sizeof(key_usage));

      if (has_key_usage) {
        if (!(key_usage & CERT_KEY_CERT_SIGN_KEY_USAGE)) {
          continue;
        }
      }

      /* We search the usage/purpose property, if present, to select
         certificates that are valid for Server Auth. if there's no property, so
         if the API fails, it means the certificate can be used for all
         purposes. */
      // DWORD usage_size = 0;
      //  if (CertGetEnhancedKeyUsage(pContext,
      //                              CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG,
      //                              nullptr,
      //                              &usage_size)) {
      //    std::vector<char> buffer(usage_size);

      //   if (!CertGetEnhancedKeyUsage(
      //           pContext,
      //           CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG,
      //           reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data()),
      //           &usage_size)) {
      //     continue;
      //   }

      //   CERT_ENHKEY_USAGE usage;
      //   std::memcpy(&usage, buffer.data(), sizeof(usage));

      //   bool found_correct_usage = false;
      //   for (DWORD i = 0; i < usage.cUsageIdentifier; ++i) {
      //     if (strcmp(usage.rgpszUsageIdentifier[i],
      //                szOID_PKIX_KP_SERVER_AUTH) == 0) {
      //       found_correct_usage = true;
      //       break;
      //     }
      //   }

      //   if (!found_correct_usage) {
      //     continue;
      //   }
      // }

      X509* x509 = d2i_X509(nullptr,
                            (const unsigned char**)&pContext->pbCertEncoded,
                            pContext->cbCertEncoded);
      if (x509) {
        DWORD str_type = CERT_SIMPLE_NAME_STR;
        DWORD str_size = CertGetNameStringW(
            pContext, CERT_NAME_RDN_TYPE, 0, &str_type, nullptr, 0);

        std::wstring name_buffer(str_size, 0);
        CertGetNameStringW(pContext,
                           CERT_NAME_RDN_TYPE,
                           0,
                           &str_type,
                           name_buffer.data(),
                           static_cast<DWORD>(name_buffer.size()));

        // std::wcout << "Loading certificate: " << name_buffer << std::endl;

        int i = X509_STORE_add_cert(store, x509);

        if (i == 0) {
          return nullptr;
        }

        X509_free(x509);
      }
    }

    CertFreeCertificateContext(pContext);
    // TODO: change flag to 0
    CertCloseStore(hStore, CERT_CLOSE_STORE_CHECK_FLAG);
  }

  if (X509_STORE_set_purpose(store, X509_PURPOSE_SSL_SERVER) == 0) {
    return nullptr;
  }

  return store;
}
} // namespace osquery
