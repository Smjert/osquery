#include <fstream>
#include <iomanip>
#include <iostream>
#include <variant>

#include <gtest/gtest.h>

#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/x509.h>

#include <windows.h>

#include <ncrypt.h>
#include <wincrypt.h>

#include <osquery/utils/windows/openssl_cng_provider/cng.h>

namespace cng {

struct CertificateAndPrivateKey {
  X509* certificate;
  EVP_PKEY* private_key;
};

struct CertificateHash {
  std::vector<BYTE> hash;
};

EVP_PKEY* sslLoadPrivateKeyFromPfx(const char* pfx_path) {
  FILE* pfx_file = fopen(pfx_path, "rb");
  if (pfx_file == nullptr) {
    // handle error
    return nullptr;
  }

  PKCS12* p12 = d2i_PKCS12_fp(pfx_file, nullptr);
  fclose(pfx_file);

  if (p12 == nullptr) {
    // handle error
    return nullptr;
  }

  EVP_PKEY* pkey = nullptr;

  if (!PKCS12_parse(p12, "", &pkey, nullptr, nullptr)) {
    // handle error
    PKCS12_free(p12);
    return nullptr;
  }

  PKCS12_free(p12);

  return pkey;
}

bool deleteCertificateFromPersonalStore(
    const std::vector<BYTE> certificate_hash) {
  HCERTSTORE store = CertOpenSystemStore(0, L"My");

  const CRYPT_HASH_BLOB hash_blob{static_cast<DWORD>(certificate_hash.size()),
                                  const_cast<BYTE*>(certificate_hash.data())};

  auto* windows_cert = CertFindCertificateInStore(
      store, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &hash_blob, nullptr);

  if (windows_cert == nullptr) {
    CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG);
    return false;
  }

  BOOL res = CertDeleteCertificateFromStore(windows_cert);

  if (!res) {
    std::cerr << "Failed to delete certificate from store, error code: "
              << GetLastError() << std::endl;
    return false;
  }

  CertFreeCertificateContext(windows_cert);

  res = CertCloseStore(store, CERT_CLOSE_STORE_CHECK_FLAG);

  if (!res) {
    std::cerr << "Failed to close the personal store, error code: "
              << GetLastError() << std::endl;
    return false;
  }

  return true;
}

std::variant<CertificateAndPrivateKey, std::string>
searchCertificateHashInStore(const std::vector<BYTE>& hash_to_find,
                             OSSL_STORE_CTX* store) {
  /*
    NOTE: The idea is that certificates always come first,
    then private keys. If we haven't found any certificate
    when we arrive to the private keys, it means the search failed.
    It's also possible that the store is somehow empty,
    so no attempt of searching either a certificate or a key is done.
  */

  X509* client_cert = nullptr;
  EVP_PKEY* client_private_key = nullptr;
  while (!OSSL_STORE_eof(store)) {
    auto* store_info = OSSL_STORE_load(store);

    if (store_info == nullptr) {
      break;
    }

    if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto* cert = OSSL_STORE_INFO_get1_CERT(store_info);

      if (cert == nullptr) {
        return std::string("Failed to extract a certificate from the store");
      }

      const EVP_MD* cert_digest = EVP_sha1();
      const auto hash_size = EVP_MD_get_size(cert_digest);
      std::vector<std::uint8_t> hash(hash_size);

      auto digest_res = X509_digest(cert, cert_digest, hash.data(), nullptr);

      if (digest_res == 0) {
        return std::string("Failed to calculate SHA digest of the certificate");
      }

      if (std::equal(hash_to_find.begin(),
                     hash_to_find.end(),
                     hash.begin(),
                     hash.end())) {
        client_cert = cert;
      }
    } else if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_PKEY) {
      if (client_cert == nullptr) {
        return std::string("No certificate found to search a private key for");
      }

      auto* pkey = OSSL_STORE_INFO_get1_PKEY(store_info);

      if (pkey == nullptr) {
        return std::string("Failed to extract a private key from the store");
      }

      // Check that this private key public part
      // corresponds to the certificate public key,
      // so we know that we have the correct private key.
      auto* pubkey = X509_get_pubkey(client_cert);

      if (pubkey == nullptr) {
        return std::string(
            "Failed to extract a public key from the certificate");
      }

      auto res = EVP_PKEY_eq(pkey, pubkey);

      if (res == 1) {
        client_private_key = pkey;
        OSSL_STORE_INFO_free(store_info);
        break;
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }

  if (client_cert == nullptr || client_private_key == nullptr) {
    return std::string("Search failed");
  }

  return CertificateAndPrivateKey{client_cert, client_private_key};
}

std::variant<CertificateHash, std::string> windowsLoadCertificateFromPFX() {
  // First import into a temporary in memory store
  // the certificate and private key from the test .pfx
  HCERTSTORE pfx_cert_store = nullptr;
  {
    std::ifstream pfx(OSQUERY_PFX_PATH, std::ios::binary);

    if (!pfx.is_open()) {
      return "Failed to open PFX certificate at " OSQUERY_PFX_PATH;
    }

    std::vector<char> pfx_buf;
    pfx.seekg(0, std::ios::end);
    pfx_buf.resize(pfx.tellg());
    pfx.seekg(0, std::ios::beg);
    pfx.read(pfx_buf.data(), pfx_buf.size());
    pfx.close();

    CRYPT_DATA_BLOB pfx_blob{static_cast<DWORD>(pfx_buf.size()),
                             reinterpret_cast<BYTE*>(pfx_buf.data())};

    pfx_cert_store =
        PFXImportCertStore(&pfx_blob,
                           nullptr,
                           CRYPT_USER_KEYSET | PKCS12_ALWAYS_CNG_KSP |
                               PKCS12_INCLUDE_EXTENDED_PROPERTIES);
  }

  if (pfx_cert_store == nullptr) {
    return std::string("Failed to import PFX, error code: ") +
           std::to_string(GetLastError());
  }

  auto personal_store = CertOpenSystemStore(0, L"My");

  if (personal_store == nullptr) {
    return std::string("Failed to open the Personal store, error code: ") +
           std::to_string(GetLastError());
  }

  // Then actually save it into the Personal store on the system
  PCCERT_CONTEXT windows_cert =
      CertEnumCertificatesInStore(pfx_cert_store, nullptr);
  PCCERT_CONTEXT cert_in_new_store = nullptr;
  auto success =
      CertAddCertificateContextToStore(personal_store,
                                       windows_cert,
                                       CERT_STORE_ADD_REPLACE_EXISTING,
                                       &cert_in_new_store);
  if (!success) {
    return std::string(
               "Failed to add certificate to Personal store, error code: ") +
           std::to_string(GetLastError());
  }

  CertFreeCertificateContext(windows_cert);

  success = CertCloseStore(pfx_cert_store, CERT_CLOSE_STORE_CHECK_FLAG);
  if (!success) {
    return std::string("Failed to close the pfx store, error code: ") +
           std::to_string(GetLastError());
  }

  // Get the certificate hash to be able to find it again via openssl
  DWORD size = 0;
  success = CertGetCertificateContextProperty(
      cert_in_new_store, CERT_HASH_PROP_ID, nullptr, &size);

  if (!success) {
    return std::string(
               "Failed to get the size of the hash property in the "
               "certificate, error code: ") +
           std::to_string(GetLastError());
  }

  std::vector<BYTE> hash_to_find(size);

  success = CertGetCertificateContextProperty(
      cert_in_new_store, CERT_HASH_PROP_ID, hash_to_find.data(), &size);

  if (!success) {
    return std::string(
               "Failed to get the hash property of the certificate, error "
               "code: ") +
           std::to_string(GetLastError());
  }

  CertFreeCertificateContext(cert_in_new_store);

  success = CertCloseStore(personal_store, CERT_CLOSE_STORE_CHECK_FLAG);

  if (!success) {
    return std::string("Failed to close the personal store, error code: ") +
           std::to_string(GetLastError());
  }

  return CertificateHash{std::move(hash_to_find)};
}

// std::optional<CertificateAndPrivateKey> searchCertificate() {}

class OpenSSLTests : public testing::Test {
 public:
  void SetUp() override {
    lib_ctx_ = OSSL_LIB_CTX_new();
    ASSERT_NE(lib_ctx_, nullptr);

    ASSERT_EQ(OSSL_PROVIDER_add_builtin(
                  lib_ctx_, "cng_provider", OsqueryCNGProviderInit),
              1);

    default_provider_ = OSSL_PROVIDER_load(lib_ctx_, "default");
    ASSERT_NE(default_provider_, nullptr);

    cng_provider_ = OSSL_PROVIDER_load(lib_ctx_, "cng_provider");
    ASSERT_NE(cng_provider_, nullptr);

    ssl_ctx_ =
        SSL_CTX_new_ex(lib_ctx_, "?provider=cng_provider", ::SSLv23_method());
    ASSERT_NE(ssl_ctx_, nullptr);
  }

  void TearDown() override {
    SSL_CTX_free(ssl_ctx_);
    ssl_ctx_ = nullptr;

    ASSERT_EQ(OSSL_PROVIDER_unload(default_provider_), 1);
    default_provider_ = nullptr;

    ASSERT_EQ(OSSL_PROVIDER_unload(cng_provider_), 1);
    cng_provider_ = nullptr;

    OSSL_LIB_CTX_free(lib_ctx_);
    lib_ctx_ = nullptr;
  }

  OSSL_LIB_CTX* lib_ctx_{nullptr};
  OSSL_PROVIDER* default_provider_{nullptr};
  OSSL_PROVIDER* cng_provider_{nullptr};
  SSL_CTX* ssl_ctx_{nullptr};
};

TEST_F(OpenSSLTests, test_open_store) {
  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("cng://MY",
                                                      lib_ctx_,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);

  ASSERT_NE(ossl_store_ctx, nullptr);

  ASSERT_EQ(OSSL_STORE_close(ossl_store_ctx), 1);
}

TEST_F(OpenSSLTests, test_count_store_elements) {
  std::vector<std::string> store_names = {"MY", "Root", "CA", "Trust"};

  for (auto& store_name : store_names) {
    const std::string uri = "cng://" + store_name;
    OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex(uri.data(),
                                                        lib_ctx_,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr,
                                                        nullptr);
    ASSERT_NE(ossl_store_ctx, nullptr);

    // NOTE: this only works because the names are ASCII
    auto store_name_w = std::wstring(store_name.begin(), store_name.end());

    auto windows_cert_store = CertOpenSystemStore(0, store_name_w.data());

    ASSERT_NE(windows_cert_store, nullptr);

    PCCERT_CONTEXT windows_cert = nullptr;
    std::size_t expected_store_elements_count = 0;
    do {
      windows_cert =
          CertEnumCertificatesInStore(windows_cert_store, windows_cert);

      if (windows_cert != nullptr) {
        ++expected_store_elements_count;
      }
    } while (windows_cert != nullptr);

    std::size_t store_elements_count = 0;
    while (!OSSL_STORE_eof(ossl_store_ctx)) {
      auto* store_info = OSSL_STORE_load(ossl_store_ctx);

      if (store_info == nullptr) {
        break;
      }

      if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
        ++store_elements_count;
      }
    }

    OSSL_STORE_close(ossl_store_ctx);

    ASSERT_EQ(store_elements_count, expected_store_elements_count);
  }
}

TEST_F(OpenSSLTests, test_find_cert) {
  HCERTSTORE cert_store = CertOpenSystemStore(0, L"Root");

  ASSERT_NE(cert_store, nullptr);

  std::vector<BYTE> hash_to_find{0x3b, 0x1e, 0xfd, 0x3a, 0x66, 0xea, 0x28,
                                 0xb1, 0x66, 0x97, 0x39, 0x47, 0x03, 0xa7,
                                 0x2c, 0xa3, 0x40, 0xa0, 0x5b, 0xd5};

  CRYPT_HASH_BLOB hash_blob{static_cast<DWORD>(hash_to_find.size()),
                            hash_to_find.data()};
  auto* windows_cert = CertFindCertificateInStore(
      cert_store, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &hash_blob, nullptr);

  // This is to verify that the certificate actually exists in the store.
  // If this fails, it likely means that a new hash to be chosen for this test.
  ASSERT_NE(windows_cert, nullptr);

  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("cng://Root",
                                                      lib_ctx_,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  ASSERT_NE(ossl_store_ctx, nullptr);

  // We loop the store to find the certificate with a specific hash
  bool cert_found = false;
  while (!OSSL_STORE_eof(ossl_store_ctx)) {
    auto* store_info = OSSL_STORE_load(ossl_store_ctx);

    if (store_info == nullptr) {
      break;
    }

    if (OSSL_STORE_INFO_get_type(store_info) == OSSL_STORE_INFO_CERT) {
      auto cert = OSSL_STORE_INFO_get0_CERT(store_info);

      ASSERT_NE(cert, nullptr);

      const EVP_MD* cert_digest = EVP_sha1();
      const auto hash_size = EVP_MD_get_size(cert_digest);
      std::vector<std::uint8_t> hash(hash_size);

      auto digest_res = X509_digest(cert, cert_digest, hash.data(), nullptr);

      ASSERT_EQ(digest_res, 1);

      if (std::equal(hash_to_find.begin(),
                     hash_to_find.end(),
                     hash.begin(),
                     hash.end())) {
        cert_found = true;
        OSSL_STORE_INFO_free(store_info);
        break;
      }
    }

    OSSL_STORE_INFO_free(store_info);
  }

  OSSL_STORE_close(ossl_store_ctx);

  ASSERT_TRUE(cert_found);
}

TEST_F(OpenSSLTests, test_client_cert_sign) {
  auto certificate_hash = windowsLoadCertificateFromPFX();

  ASSERT_TRUE(std::holds_alternative<CertificateHash>(certificate_hash))
      << std::get<std::string>(certificate_hash);

  const auto& hash_to_find = std::get<CertificateHash>(certificate_hash).hash;

  OSSL_STORE_CTX* ossl_store_ctx = OSSL_STORE_open_ex("cng://My",
                                                      lib_ctx_,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr,
                                                      nullptr);
  ASSERT_NE(ossl_store_ctx, nullptr);

  // Find again the certificate in the Personal store and the key
  // using the hash of the certificate, via our custom provider

  auto certificateAndPrivateKey =
      searchCertificateHashInStore(hash_to_find, ossl_store_ctx);

  ASSERT_TRUE(std::holds_alternative<CertificateAndPrivateKey>(
      certificateAndPrivateKey))
      << std::get<std::string>(certificateAndPrivateKey);

  auto [client_cert, client_private_key] =
      std::get<CertificateAndPrivateKey>(certificateAndPrivateKey);

  OSSL_STORE_close(ossl_store_ctx);

  ASSERT_TRUE(deleteCertificateFromPersonalStore(hash_to_find));

  std::string tosign = "SignThisMessage";

  // Sign a message with our custom provider
  // and the private key previously found
  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  EVP_PKEY_CTX* pctx = nullptr;

  ASSERT_TRUE(EVP_DigestSignInit_ex(mdctx,
                                    &pctx,
                                    OSSL_DIGEST_NAME_SHA2_256,
                                    lib_ctx_,
                                    nullptr,
                                    client_private_key,
                                    nullptr));
  ASSERT_NE(pctx, nullptr);

  ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING));

  ASSERT_TRUE(EVP_DigestSignUpdate(mdctx, tosign.data(), tosign.size()));

  std::size_t sig_size = 0;

  ASSERT_TRUE(EVP_DigestSignFinal(mdctx, nullptr, &sig_size));
  ASSERT_GT(sig_size, 0);

  std::vector<BYTE> cng_signature(sig_size);
  ASSERT_TRUE(EVP_DigestSignFinal(mdctx, cng_signature.data(), &sig_size));

  EVP_MD_CTX_free(mdctx);

  EVP_PKEY_free(client_private_key);

  // TODO: LATER, need to verify the signature with the public key
  // X509_free(client_cert);

  // Now use the openssl built-in functions to sign,
  // loading the private key from the .pfx
  EVP_PKEY* openssl_client_private_key =
      sslLoadPrivateKeyFromPfx(OSQUERY_PFX_PATH);

  ASSERT_NE(openssl_client_private_key, nullptr);
  mdctx = EVP_MD_CTX_new();

  pctx = nullptr;
  ASSERT_TRUE(EVP_DigestSignInit(
      mdctx, &pctx, EVP_sha256(), nullptr, openssl_client_private_key));

  ASSERT_TRUE(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING));

  ASSERT_TRUE(EVP_DigestSignUpdate(mdctx, tosign.data(), tosign.size()));

  sig_size = 0;

  ASSERT_TRUE(EVP_DigestSignFinal(mdctx, nullptr, &sig_size));
  ASSERT_GT(sig_size, 0);

  std::vector<BYTE> openssl_signature(sig_size);
  ASSERT_TRUE(EVP_DigestSignFinal(mdctx, openssl_signature.data(), &sig_size));

  EVP_MD_CTX_free(mdctx);

  EVP_PKEY_free(openssl_client_private_key);

  // Finally compare that the signature created with our custom provider
  // corresponds to the one created by the openssl built-in functions
  ASSERT_EQ(cng_signature, openssl_signature);

  // Now use our custom provider verify function + the client public key
  // to verify the signature
  mdctx = EVP_MD_CTX_new();
  pctx = nullptr;
  EVP_PKEY* pub_key = X509_get0_pubkey(client_cert);

  ASSERT_NE(pub_key, nullptr);

  ASSERT_TRUE(EVP_DigestVerifyInit_ex(mdctx,
                                      &pctx,
                                      OSSL_DIGEST_NAME_SHA2_256,
                                      lib_ctx_,
                                      nullptr,
                                      pub_key,
                                      nullptr));

  ASSERT_TRUE(EVP_DigestVerifyUpdate(mdctx, tosign.data(), tosign.size()));

  ASSERT_TRUE(
      EVP_DigestVerifyFinal(mdctx, cng_signature.data(), cng_signature.size()));

  EVP_MD_CTX_free(mdctx);

  pub_key = nullptr;
  X509_free(client_cert);
}

} // namespace cng
