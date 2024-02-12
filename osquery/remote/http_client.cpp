/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iomanip>
#include <iostream> // TODO: remove me
#include <optional>
#include <vector>

#include <osquery/logger/logger.h>
#include <osquery/remote/http_client.h>

#ifdef WIN32
#include <sdkddkver.h>

#include <windows.h>

#include <wincrypt.h>

#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/x509.h>

#include <osquery/utils/openssl/windows/cng_provider/cng.h>
#endif

#include <boost/asio/connect.hpp>

namespace osquery {
namespace http {

const std::string kHTTPSDefaultPort{"443"};
const std::string kHTTPDefaultPort{"80"};
const std::string kProxyDefaultPort{"3128"};

const long kSSLShortReadError{0x140000dbL};

namespace {
#ifdef WIN32
std::array<std::wstring, 2> kStores = {
    L"Root", // Trusted Root Certification Authorities
    L"CA", // Intermediate Certification Authorities
};

X509_STORE* getCurrentUserCACertificates(OSSL_LIB_CTX* lib_ctx) {
  X509_STORE* store = X509_STORE_new();
  for (const auto& store_name : kStores) {
    auto hStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM,
                      0,
                      0,
                      CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                      store_name.data());

    if (hStore == 0) {
      VLOG(1) << "Failed to open the store";
      return nullptr;
    }

    PCCERT_CONTEXT pContext = nullptr;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) !=
           nullptr) {
      /* We search the usage/purpose property, if present, to select
         certificates that are valid for Server Auth. if there's no property, so
         if the API fails, it means the certificate can be used for all
         purposes. */
      DWORD usage_size = 0;
      if (CertGetEnhancedKeyUsage(pContext,
                                  CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG,
                                  nullptr,
                                  &usage_size)) {
        std::vector<char> buffer(usage_size);

        if (!CertGetEnhancedKeyUsage(
                pContext,
                CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG,
                reinterpret_cast<PCERT_ENHKEY_USAGE>(buffer.data()),
                &usage_size)) {
          continue;
        }

        CERT_ENHKEY_USAGE usage;
        std::memcpy(&usage, buffer.data(), sizeof(usage));

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

        std::wcout << "Loading certificate: " << name_buffer << std::endl;

        int i = X509_STORE_add_cert(store, x509);

        if (i == 0) {
          VLOG(1) << "Failed to add a certificate to the CA store";
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
    VLOG(1) << "Failed to set the purpose to the store";
    return nullptr;
  }

  return store;
}

std::optional<std::pair<X509*, EVP_PKEY*>> getClientCertificate(
    const std::vector<std::uint8_t> thumbprint, OSSL_LIB_CTX* lib_ctx) {
  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("cng://MY",
                                                      lib_ctx,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  if (ossl_store_ctx == nullptr) {
    VLOG(1) << "Failed to open the store!";
    return std::nullopt;
  }

  X509* cert_test = nullptr;
  EVP_PKEY* private_key = nullptr;

  while (!OSSL_STORE_eof(ossl_store_ctx)) {
    auto* store_info = OSSL_STORE_load(ossl_store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (cert_test == nullptr &&
        OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* cert = OSSL_STORE_INFO_get1_CERT(store_info);

      if (cert != nullptr) {
        X509_NAME* subject_name = X509_get_subject_name(cert);

        char buf[1024]{};
        char* res = X509_NAME_oneline(subject_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Subject: " << buf << std::endl;
        }

        auto ex_flags = X509_get_extension_flags(cert);

        // std::cout << "Flags: " << ex_flags << std::endl;

        if (ex_flags & EXFLAG_XKUSAGE) {
          // auto ex_key_flags = X509_get_extended_key_usage(cert);
          //  std::cout << "Extended Key Usage: " << ex_key_flags << std::endl;
        }

        auto* issuer_name = X509_get_issuer_name(cert);
        res = X509_NAME_oneline(issuer_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Issuer: " << buf << std::endl;
        }

        const EVP_MD* cert_digest = EVP_sha1();
        const auto hash_size = EVP_MD_get_size(cert_digest);
        std::vector<std::uint8_t> hash(hash_size);

        VLOG(1) << "Hash size: " << hash_size << std::endl;

        // std::array<cert_digest

        if (X509_digest(cert, cert_digest, hash.data(), nullptr) == 0) {
          VLOG(1) << "Failed to calculate digest!";

          return std::nullopt;
        }

        std::stringstream hash_ss;

        for (auto c : hash) {
          hash_ss << "0x" << std::hex << std::setw(2) << std::setfill('0')
                  << (static_cast<std::uint32_t>(c) & 0xFF) << " ";
        }
        hash_ss << "\n";

        if (std::equal(thumbprint.begin(),
                       thumbprint.end(),
                       hash.begin(),
                       hash.end())) {
          cert_test = cert;
        }
      }
    } else if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
      if (cert_test == nullptr) {
        VLOG(1) << "No client certificate found";
        return std::nullopt;
      }

      VLOG(1) << "Got private key";
      private_key = OSSL_STORE_INFO_get1_PKEY(store_info);
    }

    OSSL_STORE_INFO_free(store_info);
  }

  OSSL_STORE_close(ossl_store_ctx);

  if (private_key == nullptr) {
    VLOG(1) << "No client private key found";
    return std::nullopt;
  }

  return std::make_pair(cert_test, private_key);
}
#endif
} // namespace

void Client::callNetworkOperation(std::function<void()> callback) {
  if (client_options_.timeout_) {
    timer_.async_wait(
        std::bind(&Client::timeoutHandler, this, std::placeholders::_1));
  }

  callback();

  {
    boost::system::error_code rc;
    ioc_.run(rc);
    ioc_.reset();
    if (rc) {
      ec_ = rc;
    }
  }
}

void Client::cancelTimerAndSetError(boost::system::error_code const& ec) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }

  if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

void Client::postResponseHandler(boost::system::error_code const& ec) {
  if ((ec.category() == boost::asio::error::ssl_category) &&
      (ec.value() == kSSLShortReadError)) {
    // Ignoring short read error, set ec_ to success.
    ec_.clear();
    // close connection for security reason.
    LOG(INFO) << "SSL SHORT_READ_ERROR: http_client closing socket";
    closeSocket();
  } else if (ec_ != boost::asio::error::timed_out) {
    ec_ = ec;
  }
}

bool Client::isSocketOpen() {
  return sock_.is_open();
}

void Client::closeSocket() {
  if (isSocketOpen()) {
    boost::system::error_code rc;
    sock_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, rc);
    sock_.close(rc);
  }
}

void Client::timeoutHandler(boost::system::error_code const& ec) {
  if (!ec) {
    closeSocket();
    ec_ = boost::asio::error::make_error_code(boost::asio::error::timed_out);
  }
}

void Client::connectHandler(boost::system::error_code const& ec,
                            boost::asio::ip::tcp::endpoint const&) {
  cancelTimerAndSetError(ec);
}

void Client::handshakeHandler(boost::system::error_code const& ec) {
  cancelTimerAndSetError(ec);
}

void Client::writeHandler(boost::system::error_code const& ec, size_t) {
  cancelTimerAndSetError(ec);
}

void Client::readHandler(boost::system::error_code const& ec, size_t) {
  if (client_options_.timeout_) {
    timer_.cancel();
  }
  postResponseHandler(ec);
}

void Client::createConnection() {
  std::string port = (client_options_.proxy_hostname_)
                         ? kProxyDefaultPort
                         : *client_options_.remote_port_;

  std::string connect_host = (client_options_.proxy_hostname_)
                                 ? *client_options_.proxy_hostname_
                                 : *client_options_.remote_hostname_;

  std::size_t pos;
  if ((pos = connect_host.find(":")) != std::string::npos) {
    port = connect_host.substr(pos + 1);
    connect_host = connect_host.substr(0, pos);
  }

  // We can resolve async, but there is a handle leak in Windows.
  auto results = r_.resolve(connect_host, port, ec_);
  if (!ec_) {
    callNetworkOperation([&]() {
      boost::asio::async_connect(sock_,
                                 results,
                                 std::bind(&Client::connectHandler,
                                           this,
                                           std::placeholders::_1,
                                           std::placeholders::_2));
    });
  }

  if (ec_) {
    std::string error("Failed to connect to ");
    if (client_options_.proxy_hostname_) {
      error += "proxy host ";
    }
    error += connect_host + ':' + port;
    throw std::system_error(ec_, error);
  }

  if (client_options_.keep_alive_) {
    boost::asio::socket_base::keep_alive option(true);
    sock_.set_option(option);
  }

  if (client_options_.proxy_hostname_) {
    std::string remote_host = *client_options_.remote_hostname_;
    std::string remote_port = *client_options_.remote_port_;

    beast_http_request req;
    req.method(beast_http::verb::connect);
    req.target(remote_host + ':' + remote_port);
    req.version(11);
    req.prepare_payload();

    callNetworkOperation([&]() {
      beast_http::async_write(sock_,
                              req,
                              std::bind(&Client::writeHandler,
                                        this,
                                        std::placeholders::_1,
                                        std::placeholders::_2));
    });

    if (ec_) {
      throw std::system_error(ec_);
    }

    boost::beast::flat_buffer b;
    beast_http_response_parser rp;
    rp.skip(true);

    callNetworkOperation([&]() {
      beast_http::async_read_header(sock_,
                                    b,
                                    rp,
                                    std::bind(&Client::readHandler,
                                              this,
                                              std::placeholders::_1,
                                              std::placeholders::_2));
    });

    if (ec_) {
      throw std::system_error(ec_);
    }

    if (beast_http::to_status_class(rp.get().result()) !=
        beast_http::status_class::successful) {
      throw std::runtime_error(rp.get().reason().data());
    }
  }
}

void Client::encryptConnection() {
  // boost::asio::ssl::context ctx{boost::asio::ssl::context::sslv23};

  /*
  auto* ssl_ctx = SSL_CTX_new_ex(
      cng_context.lib_ctx, "?provider=cng_provider", ::SSLv23_client_method());

  boost::asio::ssl::context ctx{ssl_ctx};

  if (client_options_.always_verify_peer_) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
  } else {
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
  }

  X509_STORE* ca_store = getCurrentUserCACertificates(cng_context.lib_ctx);

  if (ca_store == nullptr) {
    throw std::runtime_error(
        "Could not retrieve the current user CA certificates");
  }

  SSL_CTX_set_cert_store(ssl_ctx, ca_store);
  */

  // if (client_options_.server_certificate_) {
  //   ctx.set_verify_mode(boost::asio::ssl::verify_peer);
  //   ctx.load_verify_file(*client_options_.server_certificate_);
  // }

  /*
  if (client_options_.verify_path_) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.add_verify_path(*client_options_.verify_path_);
  }

  if (client_options_.ciphers_) {
    ::SSL_CTX_set_cipher_list(ctx.native_handle(),
                              client_options_.ciphers_->c_str());
  }

  if (client_options_.ssl_options_) {
    ctx.set_options(client_options_.ssl_options_);
  }
  */

  // if (client_options_.client_certificate_file_) {
  //   ctx.use_certificate_chain_file(*client_options_.client_certificate_file_);
  // }

  // if (client_options_.client_private_key_file_) {
  //   ctx.use_private_key_file(*client_options_.client_private_key_file_,
  //                            boost::asio::ssl::context::pem);
  // }

  std::vector<std::uint8_t> hash = {0xbf, 0x61, 0x7b, 0x23, 0x1f, 0x85, 0xe1,
                                    0x3e, 0x2a, 0xa9, 0x94, 0x9a, 0x61, 0x3a,
                                    0x92, 0xb9, 0x1e, 0xb9, 0x01, 0x50};

  /*
  auto opt_client_cert_data = getClientCertificate(hash, cng_context.lib_ctx);

  if (!opt_client_cert_data.has_value()) {
    throw std::runtime_error("Could not find client certificate");
  }

  auto [client_cert, client_private_key] = *opt_client_cert_data;

  if (client_cert == nullptr || client_private_key == nullptr) {
    throw std::runtime_error(
        "Failed to get a client certificate and/or private key");
  }

  auto res = SSL_CTX_use_certificate(ssl_ctx, client_cert);

  if (res != 1) {
    throw std::runtime_error("Failed to use the certificate");
  }

  res = SSL_CTX_use_PrivateKey(ssl_ctx, client_private_key);
  if (res != 1) {
    throw std::runtime_error("Failed to use the private key");
  }
  */

  ssl_sock_ = std::make_shared<ssl_stream>(sock_, ctx);
  ::SSL_set_tlsext_host_name(ssl_sock_->native_handle(),
                             client_options_.remote_hostname_->c_str());

  ssl_sock_->set_verify_callback(boost::asio::ssl::host_name_verification(
      *client_options_.remote_hostname_));

  callNetworkOperation([&]() {
    ssl_sock_->async_handshake(
        boost::asio::ssl::stream_base::client,
        std::bind(&Client::handshakeHandler, this, std::placeholders::_1));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }
}

template <typename STREAM_TYPE>
void Client::sendRequest(STREAM_TYPE& stream,
                         Request& req,
                         beast_http_response_parser& resp) {
  req.target((req.remotePath()) ? *req.remotePath() : "/");
  req.version(11);

  if (req[beast_http::field::host].empty()) {
    std::string host_header_value = *client_options_.remote_hostname_;
    if (client_options_.ssl_connection_ &&
        (kHTTPSDefaultPort != *client_options_.remote_port_)) {
      host_header_value += ':' + *client_options_.remote_port_;
    } else if (!client_options_.ssl_connection_ &&
               kHTTPDefaultPort != *client_options_.remote_port_) {
      host_header_value += ':' + *client_options_.remote_port_;
    }
    req.set(beast_http::field::host, host_header_value);
  }

  req.prepare_payload();
  req.keep_alive(true);

  if (client_options_.timeout_) {
    timer_.async_wait(
        [=](boost::system::error_code const& ec) { timeoutHandler(ec); });
  }

  beast_http_request_serializer sr{req};

  callNetworkOperation([&]() {
    beast_http::async_write(stream,
                            sr,
                            std::bind(&Client::writeHandler,
                                      this,
                                      std::placeholders::_1,
                                      std::placeholders::_2));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }

  boost::beast::flat_buffer b;

  callNetworkOperation([&]() {
    beast_http::async_read(stream,
                           b,
                           resp,
                           std::bind(&Client::readHandler,
                                     this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));
  });

  if (ec_) {
    throw std::system_error(ec_);
  }

  if (resp.get()["Connection"] == "close") {
    closeSocket();
  }

  if (!client_options_.keep_alive_) {
    closeSocket();
  }
}

bool Client::initHTTPRequest(Request& req) {
  bool create_connection = true;
  if (req.remoteHost()) {
    std::string hostname = *req.remoteHost();
    std::string port;

    if (hostname == kInstanceMetadataAuthority) {
      client_options_.proxy_hostname_ = boost::none;
    }

    if (req.remotePort()) {
      port = *req.remotePort();
    } else if (req.protocol() && (*req.protocol()).compare("https") == 0) {
      port = kHTTPSDefaultPort;
    } else {
      port = kHTTPDefaultPort;
    }

    bool ssl_connection = false;
    if (req.protocol() && (*req.protocol()).compare("https") == 0) {
      ssl_connection = true;
    }

    if (!isSocketOpen() || new_client_options_ ||
        hostname != *client_options_.remote_hostname_ ||
        port != *client_options_.remote_port_ ||
        client_options_.ssl_connection_ != ssl_connection) {
      client_options_.remote_hostname_ = hostname;
      client_options_.remote_port_ = port;
      client_options_.ssl_connection_ = ssl_connection;
      new_client_options_ = false;
      closeSocket();
    } else {
      create_connection = false;
    }
  } else {
    if (!client_options_.remote_hostname_) {
      throw std::runtime_error("Remote hostname missing");
    }

    if (!client_options_.remote_port_) {
      if (client_options_.ssl_connection_) {
        client_options_.remote_port_ = kHTTPSDefaultPort;
      } else {
        client_options_.remote_port_ = kHTTPDefaultPort;
      }
    }
    closeSocket();
  }
  return create_connection;
}

Response Client::sendHTTPRequest(Request& req) {
  if (client_options_.timeout_) {
    timer_.expires_from_now(
        boost::posix_time::seconds(client_options_.timeout_));
  }

  size_t redirect_attempts = 0;
  bool init_request = true;
  do {
    bool create_connection = true;
    if (init_request) {
      create_connection = initHTTPRequest(req);
    }

    try {
      beast_http_response_parser resp;
      if (create_connection) {
        createConnection();

        if (client_options_.ssl_connection_) {
          encryptConnection();
        }
      }

      if (client_options_.ssl_connection_) {
        sendRequest(*ssl_sock_, req, resp);
      } else {
        sendRequest(sock_, req, resp);
      }

      switch (resp.get().result()) {
      case beast_http::status::moved_permanently:
      case beast_http::status::found:
      case beast_http::status::see_other:
      case beast_http::status::not_modified:
      case beast_http::status::use_proxy:
      case beast_http::status::temporary_redirect:
      case beast_http::status::permanent_redirect: {
        if (!client_options_.follow_redirects_) {
          return Response(resp.release());
        }

        if (redirect_attempts++ >= 10) {
          throw std::runtime_error("Exceeded max of 10 redirects");
        }

        std::string redir_url = Response(resp.release()).headers()["Location"];
        if (!redir_url.size()) {
          throw std::runtime_error(
              "Location header missing in redirect response");
        }

        VLOG(1) << "HTTP(S) request re-directed to: " << redir_url;
        if (redir_url[0] == '/') {
          // Relative URI.
          if (req.remotePort()) {
            redir_url.insert(0, *req.remotePort());
            redir_url.insert(0, ":");
          }
          if (req.remoteHost()) {
            redir_url.insert(0, *req.remoteHost());
          }
          if (req.protocol()) {
            redir_url.insert(0, "://");
            redir_url.insert(0, *req.protocol());
          }
        } else {
          // Absolute URI.
          init_request = true;
        }
        req.uri(redir_url);
        break;
      }
      default:
        return Response(resp.release());
      }
    } catch (std::exception const& /* e */) {
      closeSocket();
      if (init_request && ec_ != boost::asio::error::timed_out) {
        init_request = false;
      } else {
        ec_.clear();
        throw;
      }
    }
  } while (true);
}

Response Client::put(Request& req,
                     std::string const& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body() = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string const& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body() = body;
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::put(Request& req,
                     std::string&& body,
                     std::string const& content_type) {
  req.method(beast_http::verb::put);
  req.body() = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::post(Request& req,
                      std::string&& body,
                      std::string const& content_type) {
  req.method(beast_http::verb::post);
  req.body() = std::move(body);
  if (!content_type.empty()) {
    req.set(beast_http::field::content_type, content_type);
  }
  return sendHTTPRequest(req);
}

Response Client::get(Request& req) {
  req.method(beast_http::verb::get);
  return sendHTTPRequest(req);
}

Response Client::head(Request& req) {
  req.method(beast_http::verb::head);
  return sendHTTPRequest(req);
}

Response Client::delete_(Request& req) {
  req.method(beast_http::verb::delete_);
  return sendHTTPRequest(req);
}
} // namespace http
} // namespace osquery
