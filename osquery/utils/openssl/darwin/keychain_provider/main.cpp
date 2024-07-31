
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509v3.h>

#include <array>
#include <charconv>
#include <ctime>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "keychain.h"

namespace test {
// typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

std::ofstream log(
    "/Users/bstefano/Development/openssl3-keychain/sslkeylog.log");
void sslkeylog(const SSL* ssl, const char* line) {
  log << line;
}

SSL* get_ssl(BIO* bio) {
  SSL* ssl = nullptr;
  BIO_get_ssl(bio, &ssl);
  if (ssl == nullptr) {
    std::cerr << "Error in BIO_get_ssl" << std::endl;
    ERR_print_errors_fp(stderr);
    return nullptr;
  }
  return ssl;
}

void send_http_request(BIO* bio,
                       const std::string& line,
                       const std::string& host) {
  std::string request = line + "\r\n";
  request += "Host: " + host + "\r\n";
  request += "\r\n";

  BIO_write(bio, request.data(), request.size());
  BIO_flush(bio);
}

std::string receive_some_data(BIO* bio) {
  char buffer[4096];

  int len = 0;

  do {
    len = BIO_read(bio, buffer, sizeof(buffer));
    if (len < 0) {
      continue;
    } else if (len > 0) {
      // std::cout << "Len: " << len << std::endl;
      return std::string(buffer, len);
    } else {
      std::cout << "NO DATA" << std::endl;
      break;
    }
  } while (BIO_should_retry(bio));

  if (len < 0) {
    throw std::runtime_error("Error in BIO_read");
  }

  return {};
}

std::vector<std::string_view> split_headers(const std::string_view text) {
  std::vector<std::string_view> lines;
  const char* start = text.data();
  while (const char* end = strstr(start, "\r\n")) {
    lines.push_back(std::string_view(start, end - start));
    start = end + 2;
  }
  return lines;
}

void dump_hex(const std::string& str) {
  for (auto c : str) {
    std::cout << std::hex << (static_cast<std::uint32_t>(c) & 0xFF) << " ";
  }

  std::cout << std::endl;
}

std::optional<std::string> read_chunk(BIO* bio, std::string& buffer) {
  auto search_pos = 0;
  std::size_t end_pos = 0;
  while ((end_pos = buffer.find("\r\n", search_pos)) == std::string::npos) {
    search_pos = buffer.size() > 2 ? buffer.size() - 2 : 0;
    buffer += test::receive_some_data(bio);
  }

  std::size_t chunk_size_header_size = end_pos + 2;
  // std::cout << "Chunk header size: " << chunk_size_header_size << std::endl;

  // std::cout << "Buffer: " << buffer << std::endl;

  std::string chunk_size_str = buffer.substr(0, end_pos);
  // std::cout << "chunk_size_str: " << chunk_size_str << std::endl;

  std::size_t chunk_size = stoull(buffer, nullptr, 16);
  // std::cout << "chunk_size: " << chunk_size << std::endl;

  std::size_t to_read =
      buffer.size() >= (chunk_size + 2) ? 0 : (chunk_size + 2) - buffer.size();

  // std::cout << "Buffer size: " << buffer.size() << std::endl;
  // std::cout << "Yet to read: " << to_read << std::endl;

  while (to_read > 0) {
    std::string tmp = test::receive_some_data(bio);

    if (tmp.empty()) {
      break;
    }

    buffer += tmp;
    to_read = tmp.size() > to_read ? 0 : to_read - tmp.size();
  }

  // std::cout << "Buffer size: " << buffer.size() << std::endl;

  std::string result = buffer.substr(chunk_size_header_size, chunk_size);

  if (result.empty()) {
    return std::nullopt;
  }

  std::size_t leftover =
      buffer.size() - result.size() - chunk_size_header_size - 2;
  // std::cout << "Leftover: " << leftover << std::endl;
  if (leftover > 0) {
    std::memcpy(
        buffer.data(), &buffer[chunk_size + chunk_size_header_size], leftover);
    buffer.resize(leftover);
  } else {
    buffer.clear();
  }

  return result;
}

std::string receive_http_message(BIO* bio) {
  std::string headers = test::receive_some_data(bio);

  const char headers_terminator[] = "\r\n\r\n";
  constexpr std::size_t headers_terminator_size =
      sizeof(headers_terminator) - 1;

  char* end_of_headers = strstr(&headers[0], headers_terminator);
  while (end_of_headers == nullptr) {
    headers += test::receive_some_data(bio);
    end_of_headers = strstr(&headers[0], headers_terminator);
  }

  std::size_t size = end_of_headers - &headers[0];

  std::string_view headers_view{headers.data(), size};
  auto headers_lines = test::split_headers(headers_view);

  size_t content_length = 0;
  bool chunked_read = false;
  for (auto header : headers_lines) {
    auto col = header.find(':');

    if (col == std::string::npos) {
      continue;
    }

    auto header_name = header.substr(0, col);
    auto header_value = header.substr(col + 2);

    if (header_name == "Content-Length") {
      content_length = stol(std::string(header_value));
    } else if (header_name == "Transfer-Encoding" &&
               header_value == "chunked") {
      chunked_read = true;
    }
  }

  std::string body;

  if (chunked_read) {
    std::string buffer = std::string(headers.substr(headers_view.size() + 4));

    bool has_more_data = true;
    std::optional<std::string> data;

    // std::ofstream f("C:\\parse_certs\\test.html");

    do {
      data = read_chunk(bio, buffer);

      if (!data.has_value()) {
        break;
      }

      body += *data;
      // std::cout << "Data Size: " << (*data).size() << std::endl;
      // std::cout << "Data: " << *data << std::endl;
    } while (true);

    std::cout << headers_view << std::endl;
    std::cout << body << std::endl;

  } else {
    body += std::string(headers_view.substr(headers_view.size()));

    while (body.size() < content_length) {
      std::string new_data = test::receive_some_data(bio);

      if (new_data.empty()) {
        break;
      }

      body += new_data;
    }
  }

  return headers + "\r\n" + body;
}

bool verify_the_certificate(SSL* ssl, const std::string& expected_hostname) {
  X509* cert = SSL_get_peer_certificate(ssl);
  if (cert == nullptr) {
    std::cerr << "No certificate was presented by the server" << std::endl;
    return false;
  }

  X509_print_fp(stdout, cert);

  int err = SSL_get_verify_result(ssl);
  if (err != X509_V_OK) {
    const char* message = X509_verify_cert_error_string(err);
    std::cerr << "Certificate verification error: " << message << "(" << err
              << ")" << std::endl;
    return false;
  }

  if (X509_check_host(cert,
                      expected_hostname.data(),
                      expected_hostname.size(),
                      0,
                      nullptr) != 1) {
    std::cerr << "Certificate verification error: Hostname mismatch"
              << std::endl;
    return false;
  }

  return true;
}

} // namespace test

std::vector<std::string> kStores = {"System", "SystemRoot"};

int run_test(X509_STORE* ca_store,
             X509* client_cert,
             EVP_PKEY* private_key,
             SSL_CTX* ctx) {
  // ctx = SSL_CTX_new(TLS_client_method());

  /*
    #include <openssl/ssl.h>

    typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

    void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb);
    SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX *ctx);

  */

  if (ctx == nullptr) {
    std::cerr << "Failed to create SSL context" << std::endl;
    return 1;
  }

  if (client_cert == nullptr) {
    std::cerr << "No client certificate provided!" << std::endl;
    return 1;
  }

  if (private_key == nullptr) {
    std::cerr << "No private key provided!" << std::endl;
    return 1;
  }

  SSL_CTX_set_keylog_callback(ctx, test::sslkeylog);

  SSL_CTX_set_cert_store(ctx, ca_store);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  auto res = SSL_CTX_use_certificate(ctx, client_cert);

  if (res != 1) {
    std::cerr << "Failed to use the certificate" << std::endl;
    return 1;
  }

  res = SSL_CTX_use_PrivateKey(ctx, private_key);
  if (res != 1) {
    auto error_code = ERR_get_error();
    char* err = ERR_error_string(error_code, nullptr);

    std::cerr << "Failed to use the private key: " << err << std::endl;
    return 1;
  }

  // std::string host = "www.google.com";
  // std::string host_and_port = host + ":443";

  std::string host = "localhost";
  std::string host_and_port = host + ":5000";

  BIO* sbio = BIO_new_ssl_connect(ctx);

  if (sbio == nullptr) {
    std::cerr << "Failed to create a connection to " << host_and_port
              << std::endl;
    return 1;
  }

  if (BIO_set_conn_hostname(sbio, host_and_port.data()) != 1) {
    std::cerr << "Failed to set connection hostname" << std::endl;
    BIO_free_all(sbio);
    return 1;
  }

  res = SSL_set_tlsext_host_name(test::get_ssl(sbio), host.data());

  if (res == 0) {
    std::cerr << "Failed to set SNI hostname" << std::endl;
    BIO_free_all(sbio);
    return 1;
  }

  res = SSL_set1_host(test::get_ssl(sbio), host.data());

  if (res == 0) {
    std::cerr << "Failed to set hostname" << std::endl;
    BIO_free_all(sbio);
    return 1;
  }

  if (BIO_do_connect(sbio) <= 0) {
    std::cerr << "Failed to connect to " << host_and_port << std::endl;
    ERR_print_errors_fp(stderr);
    BIO_free_all(sbio);
    return 1;
  }

  if (BIO_do_handshake(sbio) <= 0) {
    std::cerr << "Error in TLS handshake" << std::endl;
    BIO_free_all(sbio);
    return 1;
  }

  // if (!test::verify_the_certificate(test::get_ssl(sbio), host)) {
  //   std::cerr << "Failed to verify the certificate" << std::endl;
  //   return 1;
  // }

  test::send_http_request(sbio, "GET / HTTP/1.1", host);
  auto response = test::receive_http_message(sbio);

  BIO_free_all(sbio);

  // std::cout << "Response:\n" << response << std::endl;

  std::ofstream output("/tmp/openssl-keychain.log", std::ios::app);

  auto now = time(nullptr);
  output << now << "\n";
  output << response << "\n\n";

  return 0;
}

bool appendCASToStore(OSSL_LIB_CTX* lib_ctx,
                      std::string store_name,
                      X509_STORE& ca_store) {
  std::string store_uri = "keychain://" + store_name;
  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex(store_uri.data(),
                                                      lib_ctx,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  if (ossl_store_ctx == nullptr) {
    std::cerr << "Failed to open the store!" << std::endl;
    return false;
  }

  while (!OSSL_STORE_eof(ossl_store_ctx)) {
    auto* store_info = OSSL_STORE_load(ossl_store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* cert = OSSL_STORE_INFO_get0_CERT(store_info);

      if (cert != nullptr) {
        X509_NAME* subject_name = X509_get_subject_name(cert);

        char buf[1024]{};
        char* res = X509_NAME_oneline(subject_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Subject: " << buf << std::endl;
        }

        auto ex_flags = X509_get_extension_flags(cert);

        // std::cout << "Flags: " << ex_flags << std::endl;

        // if (ex_flags & EXFLAG_XKUSAGE) {
        //   auto ex_key_flags = X509_get_extended_key_usage(cert);
        //   std::cout << "Extended Key Usage: " << ex_key_flags << std::endl;
        // }

        if ((ex_flags & EXFLAG_CA) == 0) {
          // std::cout << "Certificate is not a CA" << std::endl;
          continue;
        }

        // if (ex_flags & EXFLAG_KUSAGE) {
        //   auto key_usage = X509_get_key_usage(cert);
        //   std::cout << "Certificate key usage: " << key_usage << std::endl;
        // }

        auto* issuer_name = X509_get_issuer_name(cert);
        res = X509_NAME_oneline(issuer_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Issuer: " << buf << std::endl;
        }

        X509_STORE_add_cert(&ca_store, cert);
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }

  OSSL_STORE_close(ossl_store_ctx);

  return true;
}

int main() {
  auto* lib_ctx = OSSL_LIB_CTX_new();

  std::string provider_name = "keychain_provider";

  if (OSSL_PROVIDER_add_builtin(
          lib_ctx, provider_name.c_str(), OsqueryKeychainProviderInit) != 1) {
    return 1;
  }

  OSSL_PROVIDER* default_provider = OSSL_PROVIDER_load(lib_ctx, "default");

  if (default_provider == nullptr) {
    return 1;
  }

  OSSL_PROVIDER* keychain_provider =
      OSSL_PROVIDER_load(lib_ctx, provider_name.c_str());

  if (keychain_provider == nullptr) {
    return 1;
  }

  auto ssl_ctx = SSL_CTX_new_ex(lib_ctx,
                                provider_name.insert(0, "?provider=").c_str(),
                                ::SSLv23_method());

  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("keychain://System",
                                                      lib_ctx,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  if (ossl_store_ctx == nullptr) {
    auto error_code = ERR_get_error();
    const auto* reason = ERR_error_string(error_code, nullptr);

    std::cerr << "Failed to open the System store: " << reason << std::endl;
    return 1;
  }

  X509* cert_test = nullptr;
  EVP_PKEY* private_key = nullptr;

  // std::array<std::uint8_t, 20> expected_hash = {
  //     0x76, 0xE2, 0x21, 0x67, 0x05, 0x1D, 0x87, 0x02, 0x1D, 0x9F,
  //     0xE6, 0xE0, 0x89, 0x19, 0x7B, 0x20, 0x4F, 0xEA, 0x82, 0xF1};

  std::array<std::uint8_t, 20> expected_hash = {
      0x9C, 0x15, 0x7A, 0x6E, 0x68, 0x11, 0xEA, 0x06, 0x17, 0x65,
      0x41, 0x82, 0xC2, 0x16, 0xCF, 0x77, 0x2D, 0x90, 0x4B, 0x02};

  std::cout << "---- SEARCHING FOR THE CLIENT CERT ----" << std::endl;

  while (!OSSL_STORE_eof(ossl_store_ctx)) {
    auto* store_info = OSSL_STORE_load(ossl_store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* pubkey = OSSL_STORE_INFO_get0_PUBKEY(store_info);
      auto* cert = OSSL_STORE_INFO_get1_CERT(store_info);

      if (pubkey != nullptr) {
        // std::cout << "Pubkey: " << EVP_PKEY_get0_description(pubkey)
        //         << std::endl;
      }

      if (cert != nullptr && cert_test == nullptr) {
        X509_NAME* subject_name = X509_get_subject_name(cert);

        char buf[1024]{};
        char* res = X509_NAME_oneline(subject_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Subject: " << buf << std::endl;
        }

        auto ex_flags = X509_get_extension_flags(cert);

        // std::cout << "Flags: " << ex_flags << std::endl;

        if (ex_flags & EXFLAG_XKUSAGE) {
          auto ex_key_flags = X509_get_extended_key_usage(cert);
          // std::cout << "Extended Key Usage: " << ex_key_flags << std::endl;
        }

        auto* issuer_name = X509_get_issuer_name(cert);
        res = X509_NAME_oneline(issuer_name, buf, 1024);

        if (res != nullptr) {
          // std::cout << "Issuer: " << buf << std::endl;
        }

        // auto* names = X509_get0_authority_issuer(cert);

        // if (names == nullptr) {
        //   continue;
        // }

        // for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
        //   const GENERAL_NAME* current_name = sk_GENERAL_NAME_value(names, i);

        //   if (current_name->type == GEN_DNS) {
        //     const std::uint8_t* dns_name =
        //         ASN1_STRING_get0_data(current_name->d.dNSName);

        //     std::cout << "Cert: " << reinterpret_cast<const char*>(dns_name)
        //               << std::endl;
        //   }
        // }

        const EVP_MD* cert_digest = EVP_sha1();
        const auto hash_size = EVP_MD_get_size(cert_digest);
        std::vector<std::uint8_t> hash(hash_size);

        if (X509_digest(cert, cert_digest, hash.data(), nullptr) == 0) {
          std::cerr << "Failed to calculate hash of the certificate"
                    << std::endl;
          continue;
        }

        for (const auto byte : hash) {
          std::cout << std::setw(2) << std::setfill('0') << std::hex
                    << (((std::uint32_t)byte) & 0xFF);
        }
        std::cout << std::endl;

        if (std::equal(expected_hash.begin(),
                       expected_hash.end(),
                       hash.begin(),
                       hash.end())) {
          cert_test = cert;
          std::cout << "Found certificate matching the hash" << std::endl;
        }

        // const auto* cert_data_ptr = &cert_data[0];
        // cert_test = d2i_X509(nullptr, &cert_data_ptr, cert_data.size());

        // if (cert_test == nullptr) {
        //   std::cerr << "Failed to convert the certificate data to a
        //   certificate"
        //             << std::endl;
        //   return 1;
        // }
      }
    } else if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
      auto* current_pkey = OSSL_STORE_INFO_get1_PKEY(store_info);
      auto* cert_pubkey = X509_get_pubkey(cert_test);

      if (current_pkey == nullptr) {
        break;
      }

      std::cout << "PUBKEY CERT:" << std::endl;
      BIO* keybio = BIO_new(BIO_s_mem());
      if (EVP_PKEY_print_public(keybio, cert_pubkey, 0, nullptr) == 1) {
        char buffer[1024] = {};
        while (BIO_read(keybio, buffer, 1024) > 0) {
          std::cout << buffer;
        }
      }
      std::cout << "----------" << std::endl;
      BIO_reset(keybio);

      std::cout << "PUBKEY KEY:" << std::endl;
      // BIGNUM* n = nullptr;
      // BIGNUM* e = nullptr;
      // if (EVP_PKEY_get_bn_param(current_pkey, "n", &n) != 1) {
      //   std::cout << "Failed to get N element of private key" << std::endl;
      //   ERR_print_errors_fp(stderr);
      //   continue;
      // }

      // if (EVP_PKEY_get_bn_param(current_pkey, "e", &e) != 1) {
      //   std::cout << "Failed to get E element of private key" << std::endl;
      //   ERR_print_errors_fp(stderr);
      //   continue;
      // }

      // std::cout << "N SIZE: " << BN_num_bytes(n) << std::endl;
      // std::cout << "E SIZE" << BN_num_bytes(e) << std::endl;
      if (EVP_PKEY_print_public(keybio, current_pkey, 0, nullptr) == 1) {
        char buffer[1024] = {};
        while (BIO_read(keybio, buffer, 1024) > 0) {
          std::cout << buffer;
        }
      }
      std::cout << "----------" << std::endl;
      BIO_free(keybio);

      std::cout << "Verifying if private key matches with certificate"
                << std::endl;
      if (X509_check_private_key(cert_test, current_pkey)) {
        private_key = current_pkey;
        std::cout << "Got private key: " << std::hex << private_key << std::dec
                  << std::endl;
        break;
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }
  std::cout << "---- SEARCHING FOR THE CLIENT CERT END ----" << std::endl;

  OSSL_STORE_close(ossl_store_ctx);

  // auto* ca_store = createStoreFromWindowsStore();

  X509_STORE* ca_store = X509_STORE_new();

  for (const auto store_name : kStores) {
    std::string store_name_utf8;
    for (auto c : store_name) {
      store_name_utf8.push_back(c);
    }

    appendCASToStore(lib_ctx, store_name_utf8, *ca_store);
  }

  // TODO: We need to be able to import RSA public keys that come from the
  // server certificate. This can be done by implementing OSSL_KEYMNGMT_IMPORT;
  // keydata is the output, so the key imported into our provider, the input is
  // in the OSSL_PARAMS. We have to use NCryptCreatePersistedKey but with a
  // nullptr name, so that the key is only created in memory; this way we can
  // return an handle to it, but osquery will not modify the system to do that.
  auto res = run_test(ca_store, cert_test, private_key, ssl_ctx);

  SSL_CTX_free(ssl_ctx);
  EVP_PKEY_free(private_key);
  X509_free(cert_test);
  // NOTE: No need to since the ctx takes ownership, and BIO_free_all frees it
  // X509_STORE_free(ca_store);

  OSSL_PROVIDER_unload(default_provider);
  OSSL_PROVIDER_unload(keychain_provider);

  OSSL_LIB_CTX_free(lib_ctx);
}
