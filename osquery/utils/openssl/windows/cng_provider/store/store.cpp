#include "store.h"

#include <cstring>
#include <iostream>
#include <vector>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>

#include <osquery/utils/openssl/windows/cng_provider/common/defines.h>

// #define DBGOUTPUT 1

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl
#define DBGWERR(message) std::wcerr << message << std::endl
#else
#define DBGERR(message)
#define DBGWERR(message)
#endif

extern "C" {
void* OsqueryCNGStoreOpen(void* prov_ctx, const char* uri);
int OsqueryCNGSetCtxParams(void* loader_ctx, const OSSL_PARAM params[]);
int OsqueryCNGStoreLoad(void* loaderctx,
                        OSSL_CALLBACK* object_callback,
                        void* object_callback_arg,
                        OSSL_PASSPHRASE_CALLBACK* pw_cb,
                        void* pw_cbarg);
int OsqueryCNGStoreEof(void* loader_ctx);
int OsqueryCNGStoreClose(void* loader_ctx);
}

namespace osquery {
namespace {

const std::string kUriAlgorithmPrefix = "cng://";

static const OSSL_DISPATCH cng_store_functions[]{
    {OSSL_FUNC_STORE_OPEN,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGStoreOpen)},
    {OSSL_FUNC_STORE_LOAD,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGStoreLoad)},
    {OSSL_FUNC_STORE_EOF,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGStoreEof)},
    {OSSL_FUNC_STORE_CLOSE,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGStoreClose)},
    {0, nullptr}};

} // namespace
} // namespace osquery

void* OsqueryCNGStoreOpen(void* prov_ctx, const char* uri) {
  if (prov_ctx == nullptr || uri == nullptr) {
    return nullptr;
  }

  auto uri_length = strlen(uri);

  // The URI should contain the prefix and at least one character for the store
  if (uri_length < (osquery::kUriAlgorithmPrefix.size() + 1)) {
    return nullptr;
  }

  const std::string_view uri_string(uri, uri_length);
  if (uri_string.compare(0,
                         osquery::kUriAlgorithmPrefix.size(),
                         osquery::kUriAlgorithmPrefix) != 0) {
    return nullptr;
  }

  const char* store_name = (uri + osquery::kUriAlgorithmPrefix.size());
  auto length = uri_length - osquery::kUriAlgorithmPrefix.size();

  // TODO: This should be converted to UTF16 by the stringToWString function of
  // osquery
  std::wstring store_name_utf16(&store_name[0], &store_name[length]);

  auto store = osquery::Store::openStore(store_name_utf16);

  return store;
}

int OsqueryCNGStoreLoad(void* loader_ctx,
                        OSSL_CALLBACK* object_callback,
                        void* object_callback_arg,
                        [[maybe_unused]] OSSL_PASSPHRASE_CALLBACK* pw_cb,
                        [[maybe_unused]] void* pw_cbarg) {
  if (loader_ctx == nullptr) {
    return 0;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  auto res = store->loadNextCertificate(object_callback, object_callback_arg);

  if (!res) {
    res = store->loadNextPrivateKey(object_callback, object_callback_arg);
  }

  return res;
}

int OsqueryCNGStoreEof(void* loader_ctx) {
  if (loader_ctx == nullptr) {
    return 1;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  return store->isStoreAtEof();
}

int OsqueryCNGStoreClose(void* loader_ctx) {
  if (loader_ctx == nullptr) {
    return 1;
  }

  osquery::Store* store = static_cast<osquery::Store*>(loader_ctx);

  if (!store->close()) {
    return 0;
  }

  delete store;

  return 1;
}

const OSSL_ALGORITHM* OsqueryGetStoreAlgorithms() {
  static const OSSL_ALGORITHM cng_store[] = {{"cng",
                                              osquery::algorithm_properties,
                                              osquery::cng_store_functions,
                                              "CNG Provider Implementation"},
                                             {nullptr, nullptr, nullptr}};

  return cng_store;
}

namespace osquery {

namespace {
NCRYPT_KEY_HANDLE loadPrivateKeyFromCert(PCCERT_CONTEXT cert) {
  DWORD key_spec = 0;
  BOOL caller_must_free = FALSE;
  NCRYPT_KEY_HANDLE tmp_key_handle = 0;
  BOOL retval = CryptAcquireCertificatePrivateKey(
      cert,
      CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
      nullptr,
      &tmp_key_handle,
      &key_spec,
      &caller_must_free);

  if (retval != TRUE) {
    std::wstring subject_name;
    DWORD subject_size = 0;
    DWORD error = GetLastError();

    auto res = CertNameToStrW(X509_ASN_ENCODING,
                              &cert->pCertInfo->Subject,
                              CERT_SIMPLE_NAME_STR,
                              nullptr,
                              subject_size);

    if (res != 0) {
      subject_size = res;
      subject_name.resize(subject_size);

      res = CertNameToStrW(X509_ASN_ENCODING,
                           &cert->pCertInfo->Subject,
                           CERT_SIMPLE_NAME_STR,
                           subject_name.data(),
                           subject_size);
      if (res == 0) {
        DBGERR("Failed to get the certificate subject name");
      } else {
        subject_name.pop_back();
      }
    } else {
      DBGERR("Failed to get the certificate subject name size");
    }

    DBGWERR("Failed to load private key from certificate "
            << subject_name << ", error: " << std::hex << error << std::dec);
  }

  if (caller_must_free != TRUE) {
    return 0;
  }

  DBGERR("Loading key handle: " << std::hex << tmp_key_handle << std::dec);

  return tmp_key_handle;
}

std::optional<ProviderKeyAlgorithm> getKeyAlgorithmName(
    const NCRYPT_KEY_HANDLE& key) {
  DWORD out_len;

  /* Extract the NCrypt key type name */
  SECURITY_STATUS security_status = NCryptGetProperty(
      key, NCRYPT_ALGORITHM_GROUP_PROPERTY, nullptr, 0, &out_len, 0);
  if (security_status != ERROR_SUCCESS) {
    return std::nullopt;
  }

  std::vector<wchar_t> buffer(out_len / sizeof(wchar_t), '\0');

  DWORD new_out_len;
  security_status = NCryptGetProperty(key,
                                      NCRYPT_ALGORITHM_GROUP_PROPERTY,
                                      reinterpret_cast<PBYTE>(buffer.data()),
                                      out_len,
                                      &new_out_len,
                                      0);
  if (security_status != ERROR_SUCCESS || new_out_len > out_len) {
    return std::nullopt;
  }

  if (wcsncmp(buffer.data(), NCRYPT_RSA_ALGORITHM_GROUP, out_len) == 0) {
    return ProviderKeyAlgorithm::RSA;
  }

  return std::nullopt;
}

ProviderKey searchNextValidPrivateKey(HCERTSTORE store_handle,
                                      PCCERT_CONTEXT& current_key_certificate) {
  NCRYPT_KEY_HANDLE key_handle = 0;

  do {
    current_key_certificate =
        CertEnumCertificatesInStore(store_handle, current_key_certificate);

    if (current_key_certificate == nullptr) {
      break;
    }

    key_handle = loadPrivateKeyFromCert(current_key_certificate);

    // The certificate has no private key
    if (key_handle == 0) {
      continue;
    }

    auto opt_key_algorithm = getKeyAlgorithmName(key_handle);

    // This means the algorithm of the key is not supported
    if (!opt_key_algorithm.has_value()) {
      continue;
    }

    return ProviderKey(
        key_handle, ProviderKeyType::Private, *opt_key_algorithm);
  } while (key_handle == 0);

  return {0, ProviderKeyType::Private, ProviderKeyAlgorithm::RSA};
}
} // namespace

Store* Store::openStore(const std::wstring& store_name) {
  HCERTSTORE windows_store =
      CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                    X509_ASN_ENCODING,
                    NULL,
                    CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG |
                        CERT_SYSTEM_STORE_LOCAL_MACHINE,
                    store_name.data());

  if (windows_store == nullptr) {
    return nullptr;
  }

  PCCERT_CONTEXT start_cert_context =
      CertEnumCertificatesInStore(windows_store, nullptr);
  PCCERT_CONTEXT private_key_cert = nullptr;

  ProviderKey private_key =
      searchNextValidPrivateKey(windows_store, private_key_cert);

  auto* store = new Store(windows_store,
                          start_cert_context,
                          private_key_cert,
                          std::move(private_key));

  return store;
}

Store::Store(HCERTSTORE store,
             PCCERT_CONTEXT first_certificate,
             PCCERT_CONTEXT first_key_certificate,
             ProviderKey first_private_key)
    : store_handle_(store),
      current_certificate_(first_certificate),
      certificates_eof_(current_certificate_ == nullptr),
      current_key_certificate_(first_key_certificate),
      current_private_key_(std::move(first_private_key)),
      private_keys_eof_(current_private_key_.getHandle() == 0) {}

Store::~Store() {
  close();
}

bool Store::loadNextPrivateKey(OSSL_CALLBACK* object_callback,
                               void* object_callback_arg) {
  if (private_keys_eof_ == true) {
    return false;
  }

  ProviderKeyAlgorithm algorithm = current_private_key_.getKeyAlgorithm();

  const char* key_algorithm = [&algorithm]() -> const char* {
    switch (algorithm) {
    case ProviderKeyAlgorithm::RSA: {
      return "rsaEncryption";
    }
    }

    return nullptr;
  }();

  // This should not happen, but lets be sure
  if (key_algorithm == nullptr) {
    return false;
  }

  static int object_type_pkey = OSSL_OBJECT_PKEY;
  OSSL_PARAM privkey_params[] = {
      OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE, &object_type_pkey),
      /* When given the string length 0, OSSL_PARAM_utf8_string() figures out
         the real length */
      OSSL_PARAM_utf8_string(
          OSSL_OBJECT_PARAM_DATA_TYPE,
          const_cast<void*>(reinterpret_cast<const void*>(key_algorithm)),
          0),
      /* Here we MUST use a reference, because this is not a real RSA private
         key, but just a handle. This forces openssl to make a duplicate of the
         key handle and therefore keep its own copy alive, otherwise when we
         close the store, the key handle is destroyed */
      OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                              &current_private_key_,
                              sizeof(ProviderKey*)),
      OSSL_PARAM_END};

  if (object_callback(privkey_params, object_callback_arg) == 0) {
    return false;
  }

  current_private_key_ =
      searchNextValidPrivateKey(store_handle_, current_key_certificate_);

  if (current_private_key_.getHandle() == 0) {
    private_keys_eof_ = true;
  }

  return true;
}

bool Store::loadNextCertificate(OSSL_CALLBACK* object_callback,
                                void* object_callback_arg) {
  PCCERT_CONTEXT current_certificate = current_certificate_;

  if (certificates_eof_ == true) {
    return false;
  }

  DBGERR("Cert encoding type: " << current_certificate->dwCertEncodingType);

  static constexpr auto object_type_cert = OSSL_OBJECT_CERT;
  OSSL_PARAM cert_params[] = {
      OSSL_PARAM_int(OSSL_OBJECT_PARAM_TYPE,
                     const_cast<int*>(&object_type_cert)),
      OSSL_PARAM_octet_string(OSSL_OBJECT_PARAM_DATA,
                              current_certificate->pbCertEncoded,
                              current_certificate->cbCertEncoded),
      OSSL_PARAM_END};
  object_callback(cert_params, object_callback_arg);

  PCCERT_CONTEXT next_cert_context =
      CertEnumCertificatesInStore(store_handle_, current_certificate_);
  current_certificate_ = next_cert_context;

  if (current_certificate_ == nullptr) {
    certificates_eof_ = true;
  }

  return true;
}

bool Store::close() {
  bool success = true;
  if (store_handle_ != 0) {
    if (current_certificate_ != nullptr) {
      CertFreeCertificateContext(current_certificate_);
    }
    if (current_key_certificate_ != nullptr) {
      CertFreeCertificateContext(current_key_certificate_);
    }

    // TODO: Change flag to 0
    success = CertCloseStore(store_handle_, CERT_CLOSE_STORE_CHECK_FLAG);
    store_handle_ = 0;
  }
  return success;
}

} // namespace osquery
