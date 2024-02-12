#pragma once

#include <cstdint>
#include <optional>
#include <string>
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
                         OSSL_PROVIDER& custom_provider);
  ~OpenSSLProviderContext();
  OSSL_LIB_CTX& getLibraryContext();

 private:
  OSSL_LIB_CTX* lib_ctx_{};
  OSSL_PROVIDER* default_provider_{};
  OSSL_PROVIDER* custom_provider_{};
};

struct DefaultOpenSSLContextData {
  /// Optional TLS client-auth client certificate filename.
  std::string client_certificate_file_;

  /// Optional TLS client-auth client private key filename.
  std::string client_private_key_file_;

  /// Optional TLS server-pinning server certificate/bundle filename.
  std::string server_certificate_file_;
};

struct NativeOpenSSLContextData {
  OpenSSLProviderContext* provider_context;
  X509* client_certificate_;
  X509* server_certiticates_chain_;
  EVP_PKEY* client_private_key;
};

// class IOpenSSLContextFactory {
//  public:
//   virtual ~IOpenSSLContextFactory() {}
//   virtual SSL_CTX* createNativeContext() = 0;
// };

/**
 * @brief: Factory for SSL_CTX which use default/built-in functions only
 *
 * This provides SSL_CTXs to do TLS encryption with certificates and keys
 * stored on the filesystem.
 */
SSL_CTX* createDefaultContext(const DefaultOpenSSLContextData& context_data);
SSL_CTX* createNativeContext(const NativeOpenSSLContextData& context_data);

/*#ifdef WIN32

class OpenSSLCNGContextFactory {
 public:
  OpenSSLCNGContextFactory();

  SSL_CTX* createNativeContext(OpenSSLProviderContext& provider_context,
                               X509* client_certificate_,
                               X509* server_certiticates_chain_,
                               EVP_PKEY* client_private_key_);
};

using OpenSSLContextFactory = OpenSSLCNGContextFactory;
#elif __APPLE__

class OpenSSLKeychainContextFactory {
 public:
  OpenSSLKeychainContextFactory();

  SSL_CTX* createNativeContext(OpenSSLProviderContext& provider_context,
                               X509* client_certificate_,
                               X509* server_certiticates_chain_,
                               EVP_PKEY* client_private_key_);

 private:
  OpenSSLProviderContext provider_context;
};

using OpenSSLContextFactory = OpenSSLKeychainContextFactory;
#endif*/

std::optional<OpenSSLProviderContext> createSystemOpenSSLProviderContext();

enum class UriParseError { ParseError, GenericError };

Expected<std::pair<X509*, EVP_PKEY*>, UriParseError>
getSSLClientCertificateDataFromUri(std::string_view uri);

std::optional<std::pair<X509*, EVP_PKEY*>> getSSLClientCertificateDataFromHash(
    std::vector<std::uint8_t>& hash);
std::optional<std::pair<X509*, EVP_PKEY*>>
getSSLClientCertificateDataFromCommonName(const std::string& common_name);
std::optional<X509*> getSSLSystemCAChain();

} // namespace osquery
