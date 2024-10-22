/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <fstream> // TODO: remove me
#include <iomanip>
#include <iostream> // TODO: remove me
#include <optional>
#include <vector>

#include <osquery/logger/logger.h>
#include <osquery/remote/http_client.h>

#include <boost/asio/connect.hpp>

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/trace.h>

namespace osquery {
namespace http {

const std::string kHTTPSDefaultPort{"443"};
const std::string kHTTPDefaultPort{"80"};
const std::string kProxyDefaultPort{"3128"};

const long kSSLShortReadError{0x140000dbL};

int write_cert_to_file(X509* cert, const char* filename) {
  FILE* fp;
  int ret_val;

  /* Convert certificate into PEM format */
  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    /* handle error */
    printf("Failed to create BIO for writing certificate\n");
    return -1;
  }

  /* PEM_write_bio_X509 writes the certificate 'cert' in PEM encoding to BIO bio
   */
  ret_val = PEM_write_bio_X509(bio, cert);
  if (ret_val != 1) {
    /* handle error */
    printf("Failed to write certificate into bio\n");
    BIO_free(bio);
    return -1;
  }

  /* Write the PEM-encoded certificate into the file */
  fp = fopen(filename, "w");
  if (!fp) {
    /* handle error */
    printf("Failed to open file for writing\n");
    BIO_free(bio);
    return -1;
  }

  char* pem_cert = NULL;
  long pem_cert_length = BIO_get_mem_data(bio, &pem_cert);
  fwrite(pem_cert, 1, (size_t)pem_cert_length, fp);

  printf("Writing certificate to disk: %ld\n", pem_cert_length);

  /* Cleaning up */
  BIO_free(bio);
  fclose(fp);

  return 0;
}

static std::ofstream ssl_log("/tmp/sslkeylog.txt");

void sslkeylog(const SSL* ssl, const char* line) {
  ssl_log << line << "\n";
  ssl_log.flush();
}

static size_t callback_function(
    const char* buf, size_t cnt, int category, int cmd, void* vdata) {
  /* We're not interested in the category, since it's passed to fopen() */
  /* We're not interested in vdata right now */
  switch (cmd) {
  case OSSL_TRACE_CTRL_BEGIN:
    /* A trace message begins, ensure a newline from any previous
       complete message that may have been printed */
    return fwrite("\n", 1, 1, stdout);
  case OSSL_TRACE_CTRL_WRITE:
    /* Write out the trace data as is */
    return fwrite(buf, 1, cnt, stdout);
  case OSSL_TRACE_CTRL_END:
    /* A trace message ends, finish it off with a newline */
    return fwrite("\n", 1, 1, stdout);
  }
  /* If we reach this, it means that |cmd| wasn't of understood value */
  return 0;
}

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

  std::uint32_t error_code = 0;
  const char* filename = nullptr;
  std::int32_t line = 0;
  const char* func = nullptr;
  const char* data = nullptr;
  std::int32_t flags = 0;

  while ((error_code =
              ERR_get_error_all(&filename, &line, &func, &data, &flags)) != 0) {
    char error_string[1024];
    ERR_error_string_n(error_code, error_string, sizeof(error_string));
    std::cerr << "OpenSSL Error (" << filename << ":" << func << ":" << line
              << " - " << data << ":" << flags << error_string << std::endl;
  }
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
  if (!client_options_.openssl_parameters_.has_value()) {
    throw std::runtime_error(
        "Missing certificate parameters to properly do encryption");
  }

  boost::asio::ssl::context ctx = [this]() {
    if (std::holds_alternative<DefaultOpenSSLParameters>(
            *client_options_.openssl_parameters_)) {
      boost::asio::ssl::context ctx{boost::asio::ssl::context::sslv23};

      const auto& openssl_parameters = std::get<DefaultOpenSSLParameters>(
          *client_options_.openssl_parameters_);

      if (client_options_.always_verify_peer_) {
        ctx.set_verify_mode(boost::asio::ssl::verify_peer);
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      if (!openssl_parameters.server_certificate_file_.empty()) {
        ctx.set_verify_mode(boost::asio::ssl::verify_peer);
        ctx.load_verify_file(openssl_parameters.server_certificate_file_);
      }

      if (!openssl_parameters.server_certificate_dir_.empty()) {
        ctx.set_verify_mode(boost::asio::ssl::verify_peer);
        ctx.add_verify_path(openssl_parameters.server_certificate_dir_);
      }

      if (!openssl_parameters.client_certificate_file_.empty()) {
        ctx.use_certificate_chain_file(
            openssl_parameters.client_certificate_file_);
      }

      if (!openssl_parameters.client_private_key_file_.empty()) {
        ctx.use_private_key_file(openssl_parameters.client_private_key_file_,
                                 boost::asio::ssl::context::pem);
      }

      return ctx;
    } else {
      // TODO: cleanup
      // auto start = std::chrono::system_clock::now();

      const auto& openssl_parameters = std::get<NativeOpenSSLParameters>(
          *client_options_.openssl_parameters_);
      auto* provider_library_context =
          &openssl_parameters.getSSLLibraryContext();

      auto* ssl_ctx = createNativeContext(openssl_parameters);

      SSL_CTX_set_keylog_callback(ssl_ctx, sslkeylog);

      // Set up tracing
      OSSL_trace_set_callback(OSSL_TRACE_CATEGORY_TLS, callback_function, NULL);

      // Enable all trace categories (you can customize this as needed)
      int trace_categories[] = {
          OSSL_TRACE_CATEGORY_TRACE,
          OSSL_TRACE_CATEGORY_INIT,
          OSSL_TRACE_CATEGORY_TLS,
          // Add more categories as needed
      };

      for (size_t i = 0;
           i < sizeof(trace_categories) / sizeof(trace_categories[0]);
           i++) {
        OSSL_trace_set_prefix(trace_categories[i], "OpenSSL:");
        OSSL_trace_set_suffix(trace_categories[i], "\n");
      }

      boost::asio::ssl::context ctx{ssl_ctx};

      if (client_options_.always_verify_peer_) {
        ctx.set_verify_mode(boost::asio::ssl::verify_peer);
      } else {
        ctx.set_verify_mode(boost::asio::ssl::verify_none);
      }

      if (openssl_parameters.server_search_parameters.has_value()) {
        X509_STORE* ca_store = getCABundleFromSearchParameters(
            *provider_library_context,
            *openssl_parameters.server_search_parameters);

        if (ca_store == nullptr) {
          throw std::runtime_error(
              "Could not retrieve the current user CA certificates");
        }

        ctx.set_verify_mode(boost::asio::ssl::verify_peer);

        // NOTE: The SSL_CTX takes ownership here
        SSL_CTX_set_cert_store(ssl_ctx, ca_store);
      }

      if (openssl_parameters.client_cert_search_parameters.has_value()) {
        auto opt_client_cert_data = getClientCertificateFromSearchParameters(
            *provider_library_context,
            *openssl_parameters.client_cert_search_parameters);

        if (!opt_client_cert_data.has_value()) {
          throw std::runtime_error("Could not find client certificate");
        }

        auto [client_cert, client_private_key] = *opt_client_cert_data;

        if (client_cert == nullptr || client_private_key == nullptr) {
          throw std::runtime_error(
              "Failed to get a client certificate and/or private key");
        }

        write_cert_to_file(client_cert, "/tmp/osquery_client_cert.pem");

        auto res = SSL_CTX_use_certificate(ssl_ctx, client_cert);

        if (res != 1) {
          throw std::runtime_error("Failed to use the certificate");
        }

        // TODO: check this is NOT freeing the cert, but just decreasing a ref
        X509_free(client_cert);

        res = SSL_CTX_use_PrivateKey(ssl_ctx, client_private_key);
        if (res != 1) {
          throw std::runtime_error("Failed to use the private key");
        }

        // TODO: check this is NOT freeing the cert, but just decreasing a ref
        EVP_PKEY_free(client_private_key);
      }

      // auto end = std::chrono::system_clock::now();

      // VLOG(1) << "Encrypt ms: "
      //         << std::chrono::duration_cast<std::chrono::milliseconds>(end -
      //                                                                  start)
      //                .count();

      return ctx;
    }
  }();

  if (client_options_.ciphers_) {
    ::SSL_CTX_set_cipher_list(ctx.native_handle(),
                              client_options_.ciphers_->c_str());
  }

  if (client_options_.ssl_options_) {
    ctx.set_options(client_options_.ssl_options_);
  }

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
    } catch (std::exception const& e) {
      VLOG(1) << e.what();

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
