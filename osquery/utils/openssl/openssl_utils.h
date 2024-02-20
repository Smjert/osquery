#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <openssl/provider.h>
#include <openssl/x509.h>

#include <osquery/utils/expected/expected.h>

namespace osquery {

/**
 * @brief: Necessary references to work with a custom OpenSSL provider
 *
 * To use an OpenSSL custom provider one needs to have an OpenSSL
 * library context which has the custom provider loaded in.
 * The library context will have to be used in those APIs that have
 * a variant to accept it, to be able to use the custom provider functions,
 * instead of the built-in ones.
 */
class OpenSSLProviderContext {
 public:
  OpenSSLProviderContext(OSSL_LIB_CTX& lib_ctx,
                         OSSL_PROVIDER& default_provider,
                         OSSL_PROVIDER& custom_provider)
      : lib_ctx_(&lib_ctx),
        default_provider_(&default_provider),
        custom_provider_(&custom_provider) {}

  OpenSSLProviderContext(const OpenSSLProviderContext& other) = delete;
  OpenSSLProviderContext(OpenSSLProviderContext&& other) noexcept
      : lib_ctx_(std::exchange(other.lib_ctx_, nullptr)),
        default_provider_(std::exchange(other.default_provider_, nullptr)),
        custom_provider_(std::exchange(other.custom_provider_, nullptr)) {}

  OpenSSLProviderContext& operator=(const OpenSSLProviderContext& other) =
      delete;
  OpenSSLProviderContext& operator=(OpenSSLProviderContext&& other) noexcept {
    lib_ctx_ = std::exchange(other.lib_ctx_, nullptr);
    default_provider_ = std::exchange(other.default_provider_, nullptr);
    custom_provider_ = std::exchange(other.custom_provider_, nullptr);

    return *this;
  }

  ~OpenSSLProviderContext() {
    OSSL_PROVIDER_unload(custom_provider_);
    OSSL_PROVIDER_unload(default_provider_);
    OSSL_LIB_CTX_free(lib_ctx_);
  }

  OSSL_LIB_CTX& getLibraryContext() {
    return *lib_ctx_;
  }

 private:
  OSSL_LIB_CTX* lib_ctx_{};
  OSSL_PROVIDER* default_provider_{};
  OSSL_PROVIDER* custom_provider_{};
};

struct DefaultOpenSSLParameters {
  /// Optional TLS client-auth client certificate filename.
  std::string client_certificate_file_;

  /// Optional TLS client-auth client private key filename.
  std::string client_private_key_file_;

  /// Optional TLS server-pinning server certificate/bundle filename.
  std::string server_certificate_file_;

  /// Optional TLS server-pinning server certificates/bundle directory.
  std::string server_certificate_dir_;

  bool operator==(const DefaultOpenSSLParameters& other) const {
    return client_certificate_file_ == other.client_certificate_file_ &&
           client_private_key_file_ == other.client_private_key_file_ &&
           server_certificate_file_ == other.server_certificate_file_ &&
           server_certificate_dir_ == other.server_certificate_dir_;
  }
};

class NativeOpenSSLParameters {
 public:
  NativeOpenSSLParameters(OpenSSLProviderContext& provider_context)
      : provider_context_(&provider_context) {}

  struct CertificateHash {
    std::array<std::uint8_t, 20> hash;

    bool operator==(const CertificateHash& other) const {
      return hash == other.hash;
    }
  };

  struct CertificateFields {
    std::string common_name;
    std::string organizational_unit;
    std::string issuer;

    bool operator==(const CertificateFields& other) const {
      return common_name == other.common_name &&
             organizational_unit == other.organizational_unit &&
             issuer == other.issuer;
    }
  };

  using CertificateSearchParameters =
      std::variant<CertificateHash, CertificateFields>;

  OSSL_LIB_CTX& getSSLLibraryContext() const {
    return provider_context_->getLibraryContext();
  }

  bool operator==(const NativeOpenSSLParameters& other) const {
    /* NOTE: For the provider context comparison we are stricter than usual, and
       we are only comparing the pointers, because comparing every property of
       the provider would be complex and for the use we have it doesn't make
       sense. We initialize one context for the whole osquery process and
       multiple different contexts will only happen in test code. */
    return provider_context_ == other.provider_context_ &&
           client_cert_search_parameters ==
               other.client_cert_search_parameters &&
           server_search_parameters == other.server_search_parameters;
  }

  std::optional<CertificateSearchParameters> client_cert_search_parameters;
  std::optional<CertificateFields> server_search_parameters;

 private:
  OpenSSLProviderContext* provider_context_;
};

SSL_CTX* createNativeContext(const NativeOpenSSLParameters& context_data);

std::optional<OpenSSLProviderContext> createSystemOpenSSLProviderContext();
X509_STORE* getCABundleFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateFields& search_params);

std::optional<std::pair<X509*, EVP_PKEY*>>
getClientCertificateFromSearchParameters(
    OSSL_LIB_CTX& lib_ctx,
    const NativeOpenSSLParameters::CertificateSearchParameters& search_params);

} // namespace osquery
