#include "openssl_utils.h"

#include <openssl/x509v3.h>

namespace osquery {

#ifdef WIN32
const char* clientCertStoreUri = "cng://MY";
#else
const char* clientCertStoreUri = "keychain://System";
#endif

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

      if (found_private_key == nullptr) {
        return std::nullopt;
      }

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

        /* If we have a key usage, let's ensure that we have at least
           Digital Signature */
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

        bool certificate_found = true;

        if (!cert_fields.common_name.empty()) {
          // We set it to false here because we have CN to search for,
          // but we don't know yet if we've found it
          certificate_found = false;
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

        if (certificate_found && !cert_fields.organizational_unit.empty()) {
          certificate_found = false;
          std::array<char, 65> cert_organization_unit;
          std::uint32_t buffer_length =
              static_cast<std::uint32_t>(cert_organization_unit.size());
          if (X509_NAME_get_text_by_NID(subject_name,
                                        NID_organizationalUnitName,
                                        cert_organization_unit.data(),
                                        buffer_length)) {
            // TODO: This should actually be a lowercase check and ignore
            // leading or following whitespaces
            if (cert_fields.organizational_unit ==
                cert_organization_unit.data()) {
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

std::optional<std::pair<X509*, EVP_PKEY*>>
getClientCertificateFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateSearchParameters& search_params) {
  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex(clientCertStoreUri,
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
} // namespace osquery
