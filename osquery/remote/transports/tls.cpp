/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "tls.h"

#include <charconv>
#include <chrono>
#include <variant>
#include <vector>

#include <osquery/core/core.h>
#include <osquery/core/init.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/config/default_paths.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/info/version.h>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace osquery {

const std::string kTLSUserAgentBase = "osquery/";

const std::string_view kFilePrefix = "file://";
const std::string_view kCertPrefix = "cert://";

/// TLS server hostname.
CLI_FLAG(string,
         tls_hostname,
         "",
         "TLS/HTTPS hostname for Config, Logger, and Enroll plugins");

/// Optional HTTP proxy server hostname.
CLI_FLAG(string, proxy_hostname, "", "Optional HTTP proxy hostname");

/// Path to optional TLS server/CA certificate(s), used for pinning.
CLI_FLAG(string,
         tls_server_certs,
         OSQUERY_CERTS_HOME "certs.pem",
         "Optional path to a TLS server PEM certificate(s) bundle");

/// Path to optional TLS client certificate, used for enrollment/requests.
CLI_FLAG(string,
         tls_client_cert,
         "",
         "Optional path to a TLS client-auth PEM certificate");

/// Path to optional TLS client secret key, used for enrollment/requests.
CLI_FLAG(string,
         tls_client_key,
         "",
         "Optional path to a TLS client-auth PEM private key");

/// Reuse TLS session sockets.
CLI_FLAG(bool, tls_session_reuse, true, "Reuse TLS session sockets");

/// Tear down TLS sessions after a custom timeout.
CLI_FLAG(uint32,
         tls_session_timeout,
         3600,
         "TLS session keep alive timeout in seconds");

#ifndef NDEBUG
HIDDEN_FLAG(bool,
            tls_allow_unsafe,
            false,
            "Allow TLS server certificate trust failures");
#endif

HIDDEN_FLAG(bool,
            tls_dump,
            false,
            "Print remote requests and responses to stderr");

/// Undocumented feature to override TLS endpoints.
HIDDEN_FLAG(bool, tls_node_api, false, "Use node key as TLS endpoints");

DECLARE_bool(verbose);

namespace {
enum class OpenSSLMode { Default, Native };

constexpr bool isUnsafeTLSDisabled() {
#ifndef NDEBUG
  return !FLAGS_tls_allow_unsafe;
#else
  return true;
#endif
}

std::optional<OpenSSLMode> detectOpenSSLMode(std::string_view uri) {
  if (uri.substr(0, kFilePrefix.size()) == kFilePrefix) {
    return OpenSSLMode::Default;
  }

  if (uri.substr(0, kCertPrefix.size()) == kCertPrefix) {
    return OpenSSLMode::Native;
  }

  return std::nullopt;
}

std::optional<NativeOpenSSLParameters::CertificateSearchParameters>
parseCertParams(std::string_view cert_params_string) {
  // TODO: parse for cert://all mode

  if (cert_params_string == "all") {
    return NativeOpenSSLParameters::CertificateFields{};
  }

  std::vector<std::string_view> parts = vsplit(cert_params_string, ':');

  // TODO: Format is not correct, give error
  if (parts.empty() || parts.size() % 2 != 0) {
    return std::nullopt;
  }

  if (parts[0] == "hash") {
    const auto& hash_string = parts[1];

    if (hash_string.size() != 40) {
      return std::nullopt;
    }

    NativeOpenSSLParameters::CertificateHash cert_hash{};

    for (std::size_t i = 0; i < hash_string.size(); i += 2) {
      std::uint8_t byte;
      auto [_, ec] = std::from_chars(
          hash_string.data() + i, hash_string.data() + i + 2, byte, 16);

      if (ec != std::errc()) {
        return std::nullopt;
      }

      cert_hash.hash[i / 2] = byte;
    }

    return cert_hash;
  }

  NativeOpenSSLParameters::CertificateFields cert_fields;

  for (std::size_t i = 0; i < parts.size(); i += 2) {
    const auto& part = parts[i];
    if (part == "cn") {
      cert_fields.common_name = parts[i + 1];
    } else if (part == "ou") {
      cert_fields.organizational_unit = parts[i + 1];
    } else {
      // TODO: Give error, wrong format
      return std::nullopt;
    }
  }

  return cert_fields;
}

http::Client::Options createCommonOptions(bool verify_peer) {
  http::Client::Options options;
  options.follow_redirects(true).timeout(16);
  // Configuration may allow unsafe TLS testing if compiled as a debug target.
  if (isUnsafeTLSDisabled()) {
    options.always_verify_peer(verify_peer);
  } else {
    options.always_verify_peer(false);
  }

  return options;
}

std::optional<std::variant<DefaultOpenSSLParameters, NativeOpenSSLParameters>>
createOpenSSLParametersFrom(std::string client_certificate_uri,
                            std::string client_private_key_uri,
                            std::string server_certificate_uri) {
  auto last_detected_openssl_mode = OpenSSLMode::Default;
  std::string_view client_certificate_params;
  std::string_view client_private_key_params;
  std::string_view server_certificate_params;

  if (!server_certificate_uri.empty()) {
    auto opt_openssl_mode = detectOpenSSLMode(server_certificate_uri);

    if (!opt_openssl_mode.has_value()) {
      LOG(ERROR) << "Could not properly parse the tls_server_certs flag, "
                    "format was incorrect";
      return std::nullopt;
    }

    last_detected_openssl_mode = *opt_openssl_mode;

    if (last_detected_openssl_mode == OpenSSLMode::Default) {
      server_certificate_params =
          std::string_view(server_certificate_uri.data() + kFilePrefix.size(),
                           server_certificate_uri.size() - kFilePrefix.size());
    } else {
      server_certificate_params =
          std::string_view(server_certificate_uri.data() + kCertPrefix.size(),
                           server_certificate_uri.size() - kCertPrefix.size());
    }
  }

  if (!client_certificate_uri.empty()) {
    auto opt_openssl_mode = detectOpenSSLMode(client_certificate_uri);

    if (!opt_openssl_mode.has_value()) {
      LOG(ERROR) << "Could not properly parse the tls_client_cert flag, "
                    "format was incorrect";
      return std::nullopt;
    }

    if (*opt_openssl_mode != last_detected_openssl_mode) {
      LOG(ERROR) << "Cannot mix filesystem and native store mode in the "
                    "client/server certificates and private key options";
      return std::nullopt;
    }

    last_detected_openssl_mode = *opt_openssl_mode;

    if (last_detected_openssl_mode == OpenSSLMode::Default) {
      client_certificate_params =
          std::string_view(client_certificate_uri.data() + kFilePrefix.size(),
                           client_certificate_uri.size() - kFilePrefix.size());
    } else {
      client_certificate_params =
          std::string_view(client_certificate_uri.data() + kCertPrefix.size(),
                           client_certificate_uri.size() - kCertPrefix.size());
    }
  }

  // TODO: Cleanup, group this with the client cert check, since they need to be
  // both present
  if (!client_private_key_uri.empty()) {
    auto opt_openssl_mode = detectOpenSSLMode(client_certificate_uri);

    if (!opt_openssl_mode.has_value()) {
      LOG(ERROR) << "Could not properly parse the tls_client_cert flag, "
                    "format was incorrect";
      return std::nullopt;
    }

    if (*opt_openssl_mode != last_detected_openssl_mode) {
      LOG(ERROR) << "Cannot mix filesystem and native store mode in the "
                    "client/server certificates and private key options";
      return std::nullopt;
    }

    if (last_detected_openssl_mode != OpenSSLMode::Default) {
      LOG(WARNING)
          << "The tls_client_key option must be of the format file://<path to "
             "private key on filesystem>, it cannot be in native store form. "
             "Value will be ignored.";
    }

    client_private_key_params =
        std::string_view(client_private_key_uri.data() + kFilePrefix.size(),
                         client_private_key_uri.size() - kFilePrefix.size());
  }

  if (last_detected_openssl_mode == OpenSSLMode::Default) {
    DefaultOpenSSLParameters openssl_parameters{};

    if (!server_certificate_params.empty()) {
      auto server_certificate_path = boost::filesystem::path(
          server_certificate_params.begin(), server_certificate_params.end());

      if (!osquery::isReadable(server_certificate_path).ok()) {
        LOG(WARNING) << "Cannot read TLS server certificate(s): "
                     << server_certificate_params;
        return DefaultOpenSSLParameters{};
      }

      // There is a non-default server certificate set.
      boost::system::error_code ec;

      auto status = fs::status(server_certificate_path, ec);

      // In unsafe mode we would skip verification of the server's TLS details
      // to allow people to connect to devservers
      if (isUnsafeTLSDisabled()) {
        openssl_parameters.server_certificate_file_ =
            server_certificate_path.string();
      }

      // On Windows, we cannot set openssl_certificate to a directory
      if (isPlatform(PlatformType::TYPE_WINDOWS) &&
          status.type() != fs::regular_file) {
        LOG(WARNING) << "Cannot set a non-regular file as a certificate: "
                     << server_certificate_params;
      } else if (isUnsafeTLSDisabled()) {
        openssl_parameters.server_certificate_dir_ =
            server_certificate_path.string();
      }
    }

    if (!client_certificate_params.empty() &&
        !client_private_key_params.empty()) {
      auto client_certificate_path = boost::filesystem::path(
          client_certificate_params.begin(), client_certificate_params.end());

      auto client_private_key_path = boost::filesystem::path(
          client_private_key_params.begin(), client_private_key_params.end());

      if (!osquery::isReadable(client_certificate_path).ok()) {
        LOG(WARNING) << "Cannot read TLS client certificate: "
                     << client_certificate_params;
      } else if (!osquery::isReadable(client_private_key_path).ok()) {
        LOG(WARNING) << "Cannot read TLS client private key: "
                     << client_private_key_params;
      } else {
        openssl_parameters.client_certificate_file_ = client_certificate_params;
        openssl_parameters.client_private_key_file_ = client_private_key_params;
        VLOG(1) << "client cert: "
                << openssl_parameters.client_certificate_file_;
        VLOG(1) << "client priv key: "
                << openssl_parameters.client_private_key_file_;
      }
    }

    return openssl_parameters;

  } else {
    NativeOpenSSLParameters openssl_parameters{
        Initializer::getOpenSSLCustomProviderContext()};
    if (!server_certificate_params.empty()) {
      auto opt_cert_params = parseCertParams(server_certificate_params);

      if (!opt_cert_params.has_value()) {
        LOG(WARNING) << "Could not properly parse the tls_server_certs flag, "
                        "format was incorrect";
        return openssl_parameters;
      }

      last_detected_openssl_mode = OpenSSLMode::Native;

      openssl_parameters.server_search_parameters =
          std::get<NativeOpenSSLParameters::CertificateFields>(
              *opt_cert_params);
    }

    if (!client_certificate_params.empty()) {
      auto opt_cert_params = parseCertParams(client_certificate_params);

      if (!opt_cert_params.has_value()) {
        LOG(WARNING) << "Could not properly parse the tls_client_certs flag, "
                        "format was incorrect";
        return openssl_parameters;
      }

      last_detected_openssl_mode = OpenSSLMode::Native;

      openssl_parameters.client_cert_search_parameters =
          std::get<NativeOpenSSLParameters::CertificateFields>(
              *opt_cert_params);
    }

    return openssl_parameters;
  }

  return std::nullopt;
}
} // namespace

TLSTransport::TLSTransport()
    : server_certificate_file_(FLAGS_tls_server_certs),
      client_certificate_file_(FLAGS_tls_client_cert),
      client_private_key_file_(FLAGS_tls_client_key) {}

void TLSTransport::decorateRequest(http::Request& r) {
  r << http::Request::Header("Content-Type", serializer_->getContentType());
  r << http::Request::Header("Accept", serializer_->getContentType());
  r << http::Request::Header("User-Agent", kTLSUserAgentBase + kVersion);
}

http::Client::Options TLSTransport::getOptions() {
  http::Client::Options options = createCommonOptions(verify_peer_);

  auto openssl_cert_parameters =
      createOpenSSLParametersFrom({}, {}, server_certificate_file_);

  options.openssl_set_cert_parameters(openssl_cert_parameters);

  return options;
}

http::Client::Options TLSTransport::getInternalOptions() {
  auto start = std::chrono::system_clock::now();

  http::Client::Options options = createCommonOptions(verify_peer_);

  auto openssl_cert_parameters =
      createOpenSSLParametersFrom(client_certificate_file_,
                                  client_private_key_file_,
                                  server_certificate_file_);

  options.openssl_set_cert_parameters(openssl_cert_parameters);

  options.keep_alive(FLAGS_tls_session_reuse);

  if (FLAGS_proxy_hostname.size() > 0) {
    options.proxy_hostname(FLAGS_proxy_hostname);
  }

  options.openssl_ciphers(kTLSCiphers);
  options.openssl_options(SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1 |
                          SSL_OP_NO_TLSv1_1 | SSL_OP_ALL);

  auto end = std::chrono::system_clock::now();

  VLOG(1) << "Getting options ms: "
          << std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
                 .count();

  return options;
}

inline bool tlsFailure(const std::string& what) {
  if (what.find("Error") == 0 || what.find("refused") != std::string::npos) {
    return false;
  }
  return true;
}

static auto getClient() {
  std::shared_ptr<http::Client> client = nullptr;
  if (FLAGS_tls_session_reuse) {
    thread_local std::shared_ptr<http::Client> tl_client;
    thread_local auto last_time_reseted = std::chrono::system_clock::now();
    client = tl_client;

    if (client.get() == nullptr) {
      tl_client = client = std::make_shared<http::Client>();
    }

    if (FLAGS_tls_session_timeout > 0 &&
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - last_time_reseted)
                .count() > FLAGS_tls_session_timeout) {
      tl_client.reset();
      last_time_reseted = std::chrono::system_clock::now();
    }
  } else {
    client = std::make_shared<http::Client>();
  }
  return client;
}

void printRawStderr(const std::string& s) {
  fprintf(stderr, "%s\n", s.c_str());
}

Status TLSTransport::sendRequest() {
  if (destination_.find("https://") == std::string::npos) {
    return Status::failure(
        "Cannot create TLS request for non-HTTPS protocol URI");
  }

  http::Request r(destination_);
  decorateRequest(r);

  VLOG(1) << "TLS/HTTPS GET request to URI: " << destination_;
  try {
    std::shared_ptr<http::Client> client = getClient();

    client->setOptions(getInternalOptions());
    response_ = client->get(r);

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      // Not using VLOG to avoid logging whole body to logging destination.
      printRawStderr(response_body);
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status::failure(std::string("Request error: ") + e.what());
  }
  return response_status_;
}

Status TLSTransport::sendRequest(const std::string& params, bool compress) {
  if (destination_.find("https://") == std::string::npos) {
    return Status::failure(
        "Cannot create TLS request for non-HTTPS protocol URI");
  }

  http::Request r(destination_);
  decorateRequest(r);
  if (compress) {
    // Later, when posting/putting, the data will be optionally compressed.
    r << http::Request::Header("Content-Encoding", "gzip");
  }

  // Allow request calls to override the default HTTP POST verb.
  HTTPVerb verb;
  auto it = options_.doc().FindMember("_verb");

  verb = (HTTPVerb)(it != options_.doc().MemberEnd() && it->value.IsInt()
                        ? it->value.GetInt()
                        : HTTP_POST);

  VLOG(1) << "TLS/HTTPS " << ((verb == HTTP_POST) ? "POST" : "PUT")
          << " request to URI: " << destination_;
  if (FLAGS_verbose && FLAGS_tls_dump) {
    // Not using VLOG to avoid logging whole body to logging
    // destination.
    printRawStderr(params);
  }

  try {
    std::shared_ptr<http::Client> client = getClient();
    client->setOptions(getInternalOptions());

    if (verb == HTTP_POST) {
      response_ = client->post(r, (compress) ? compressString(params) : params);
    } else {
      response_ = client->put(r, (compress) ? compressString(params) : params);
    }

    const auto& response_body = response_.body();
    if (FLAGS_verbose && FLAGS_tls_dump) {
      // Not using VLOG to avoid logging whole body to logging
      // destination.
      printRawStderr(response_body);
    }
    response_status_ =
        serializer_->deserialize(response_body, response_params_);
  } catch (const std::exception& e) {
    return Status::failure(std::string("Request error: ") + e.what());
  }
  return response_status_;
}
} // namespace osquery
