#include "key_management.h"

#include <iostream>
#include <string>
#include <vector>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

#include <osquery/utils/openssl/windows/cng_provider/common/defines.h>
#include <osquery/utils/openssl/windows/cng_provider/keymanagement/provider_key.h>

// #define DBGOUTPUT 1

#ifdef DBGOUTPUT
#define DBGERR(message) std::cerr << message << std::endl
#define DBGWERR(message) std::wcerr << message << std::endl
#else
#define DBGERR(message)
#define DBGWERR(message)
#endif

extern "C" {
void* OsqueryCNGKeyManagementNew(void* prov_ctx);
void OsqueryCNGKeyManagementFree(void* key_data);
void* OsqueryCNGKeyManagementLoad(const void* reference, size_t reference_size);
int OsqueryCNGKeyManagementGetParams(void* key_data, OSSL_PARAM params[]);
const OSSL_PARAM* OsqueryCNGKeyManagementGetTableParams();
int OsqueryCNGKeyManagementHas(const void* key_data, int selection);
int OsqueryCNGKeyManagementExport(const void* key_data,
                                  int selection,
                                  OSSL_CALLBACK* param_callback,
                                  void* callback_arg);
const OSSL_PARAM* OsqueryCNGKeyManagementExportTypes(int selection);
int OsqueryCNGKeyManagementImport(void* key_data,
                                  int selection,
                                  const OSSL_PARAM params[]);
const OSSL_PARAM* OsqueryCNGKeyManagementImportTypes(int selection);
}

namespace osquery {

namespace {

static const OSSL_DISPATCH key_management_functions[]{
    {OSSL_FUNC_KEYMGMT_NEW,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementNew)},
    {OSSL_FUNC_KEYMGMT_DUP,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementDup)},
    {OSSL_FUNC_KEYMGMT_FREE,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementFree)},
    {OSSL_FUNC_KEYMGMT_LOAD,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementLoad)},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementGetParams)},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
     reinterpret_cast<OSSLCNGFunctionPtr>(
         OsqueryCNGKeyManagementGetTableParams)},
    {OSSL_FUNC_KEYMGMT_HAS,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementHas)},
    {OSSL_FUNC_KEYMGMT_EXPORT,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementExport)},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementExportTypes)},
    {OSSL_FUNC_KEYMGMT_IMPORT,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementImport)},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
     reinterpret_cast<OSSLCNGFunctionPtr>(OsqueryCNGKeyManagementImportTypes)},
    {0, nullptr}};

/*
 * Define a scaling constant for our fixed point arithmetic.
 * This value must be a power of two because the base two logarithm code
 * makes this assumption.  The exponent must also be a multiple of three so
 * that the scale factor has an exact cube root.  Finally, the scale factor
 * should not be so large that a multiplication of two scaled numbers
 * overflows a 64 bit unsigned integer.
 */
constexpr unsigned int scale = 1 << 18;
constexpr unsigned int cbrt_scale = 1 << (2 * 18 / 3);

constexpr unsigned int log_2 = 0x02c5c8; /* scale * log(2) */
constexpr unsigned int log_e = 0x05c551; /* scale * log2(M_E) */
constexpr unsigned int c1_923 = 0x07b126; /* scale * 1.923 */
constexpr unsigned int c4_690 = 0x12c28f; /* scale * 4.690 */

/*
 * Multiply two scaled integers together and rescale the result.
 */
static inline std::uint64_t mul2(std::uint64_t a, std::uint64_t b) {
  return a * b / scale;
}

/*
 * Calculate the cube root of a 64 bit scaled integer.
 * Although the cube root of a 64 bit number does fit into a 32 bit unsigned
 * integer, this is not guaranteed after scaling, so this function has a
 * 64 bit return.  This uses the shifting nth root algorithm with some
 * algebraic simplifications.
 */
static std::uint64_t icbrt64(std::uint64_t x) {
  std::uint64_t r = 0;
  std::uint64_t b;
  int s;

  for (s = 63; s >= 0; s -= 3) {
    r <<= 1;
    b = 3 * r * (r + 1) + 1;
    if ((x >> s) >= b) {
      x -= b << s;
      r++;
    }
  }
  return r * cbrt_scale;
}

/*
 * Calculate the natural logarithm of a 64 bit scaled integer.
 * This is done by calculating a base two logarithm and scaling.
 * The maximum logarithm (base 2) is 64 and this reduces base e, so
 * a 32 bit result should not overflow.  The argument passed must be
 * greater than unity so we don't need to handle negative results.
 */
static std::uint32_t ilog_e(std::uint64_t v) {
  std::uint32_t i, r = 0;

  /*
   * Scale down the value into the range 1 .. 2.
   *
   * If fractional numbers need to be processed, another loop needs
   * to go here that checks v < scale and if so multiplies it by 2 and
   * reduces r by scale.  This also means making r signed.
   */
  while (v >= 2 * scale) {
    v >>= 1;
    r += scale;
  }
  for (i = scale / 2; i != 0; i /= 2) {
    v = mul2(v, v);
    if (v >= 2 * scale) {
      v >>= 1;
      r += i;
    }
  }
  r = (r * static_cast<std::uint64_t>(scale)) / log_e;
  return r;
}

// Lifted from OpenSSL; see ossl_ifc_ffc_compute_security_bits
/*
 * NIST SP 800-56B rev 2 Appendix D: Maximum Security Strength Estimates for IFC
 * Modulus Lengths.
 *
 * Note that this formula is also referred to in SP800-56A rev3 Appendix D:
 * for FFC safe prime groups for modp and ffdhe.
 * After Table 25 and Table 26 it refers to
 * "The maximum security strength estimates were calculated using the formula in
 * Section 7.5 of the FIPS 140 IG and rounded to the nearest multiple of eight
 * bits".
 *
 * The formula is:
 *
 * E = \frac{1.923 \sqrt[3]{nBits \cdot log_e(2)}
 *           \cdot(log_e(nBits \cdot log_e(2))^{2/3} - 4.69}{log_e(2)}
 * The two cube roots are merged together here.
 */
int RSABitsToSecurityBits(int n) {
  std::uint64_t x;
  std::uint32_t lx;
  std::uint16_t y, cap;

  /*
   * Look for common values as listed in standards.
   * These values are not exactly equal to the results from the formulae in
   * the standards but are defined to be canonical.
   */
  switch (n) {
  case 2048: /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
    return 112;
  case 3072: /* SP 800-56B rev 2 Appendix D and FIPS 140-2 IG 7.5 */
    return 128;
  case 4096: /* SP 800-56B rev 2 Appendix D */
    return 152;
  case 6144: /* SP 800-56B rev 2 Appendix D */
    return 176;
  case 7680: /* FIPS 140-2 IG 7.5 */
    return 192;
  case 8192: /* SP 800-56B rev 2 Appendix D */
    return 200;
  case 15360: /* FIPS 140-2 IG 7.5 */
    return 256;
  }

  /*
   * The first incorrect result (i.e. not accurate or off by one low) occurs
   * for n = 699668.  The true value here is 1200.  Instead of using this n
   * as the check threshold, the smallest n such that the correct result is
   * 1200 is used instead.
   */
  if (n >= 687737)
    return 1200;
  if (n < 8)
    return 0;

  /*
   * To ensure that the output is non-decreasing with respect to n,
   * a cap needs to be applied to the two values where the function over
   * estimates the strength (according to the above fast path).
   */
  if (n <= 7680)
    cap = 192;
  else if (n <= 15360)
    cap = 256;
  else
    cap = 1200;

  x = n * static_cast<std::uint64_t>(log_2);
  lx = ilog_e(x);
  y = static_cast<std::uint16_t>(
      ((mul2(c1_923, icbrt64(mul2(mul2(x, lx), lx))) - c4_690)) / log_2);
  y = (y + 4) & ~7;
  if (y > cap)
    y = cap;
  return y;
}
} // namespace
} // namespace osquery

void* OsqueryCNGKeyManagementNew([[maybe_unused]] void* prov_ctx) {
  // TODO: For now we only support RSA keys, but here the key management has to
  // know which key it has to initialize
  return new osquery::ProviderKey{
      0, osquery::ProviderKeyType::Public, osquery::ProviderKeyAlgorithm::RSA};
}

void OsqueryCNGKeyManagementFree(void* key_data) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  DBGERR("Freeing key: " << std::hex << provider_key->getHandle() << std::dec);

  delete provider_key;
}

void* OsqueryCNGKeyManagementLoad(const void* reference,
                                  [[maybe_unused]] size_t reference_size) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(reference);

  return OsqueryCNGKeyManagementDup(provider_key, OSSL_KEYMGMT_SELECT_ALL);
}

int OsqueryCNGKeyManagementGetParams(void* key_data, OSSL_PARAM params[]) {
  if (key_data == nullptr) {
    return 0;
  }

  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  OSSL_PARAM* param;
  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);

  if (param != nullptr) {
    DWORD key_length;
    DWORD received_bytes;
    SECURITY_STATUS security_status =
        NCryptGetProperty(provider_key->getHandle(),
                          NCRYPT_LENGTH_PROPERTY,
                          reinterpret_cast<PBYTE>(&key_length),
                          sizeof(key_length),
                          &received_bytes,
                          0);
    if (security_status != ERROR_SUCCESS ||
        received_bytes != sizeof(key_length)) {
      return 0;
    }

    if (!OSSL_PARAM_set_int(param, key_length)) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);

  if (param != nullptr) {
    DWORD key_length;
    DWORD received_bytes;
    SECURITY_STATUS security_status =
        NCryptGetProperty(provider_key->getHandle(),
                          NCRYPT_LENGTH_PROPERTY,
                          reinterpret_cast<PBYTE>(&key_length),
                          sizeof(key_length),
                          &received_bytes,
                          0);
    if (security_status != ERROR_SUCCESS ||
        received_bytes != sizeof(key_length)) {
      return 0;
    }

    if (!OSSL_PARAM_set_int(param,
                            osquery::RSABitsToSecurityBits(key_length))) {
      return 0;
    }
  }

  param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);

  if (param != nullptr) {
    // See RSA:
    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-cryptographic-algorithm-providers
    if (!OSSL_PARAM_set_int(param, 16384)) {
      return 0;
    }
  }

  return 1;
}

const OSSL_PARAM* OsqueryCNGKeyManagementGetTableParams() {
  static const OSSL_PARAM key_management_param_types[] = {
      OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_DEFN(
          OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_DEFN(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, nullptr, 0),
      OSSL_PARAM_END};

  return key_management_param_types;
}

int OsqueryCNGKeyManagementHas(const void* key_data, int selection) {
  DWORD cng_desired_key_usages = 0;

  if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
    cng_desired_key_usages |= NCRYPT_ALLOW_DECRYPT_FLAG;
  }

  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    cng_desired_key_usages |= NCRYPT_ALLOW_SIGNING_FLAG;
  }

  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  DBGERR("Checking if key at handle " << std::hex << provider_key->getHandle()
                                      << " has " << cng_desired_key_usages
                                      << std::dec);

  if (cng_desired_key_usages != 0) {
    DWORD cng_key_usages;
    DWORD received_bytes;

    SECURITY_STATUS security_status =
        NCryptGetProperty(provider_key->getHandle(),
                          NCRYPT_KEY_USAGE_PROPERTY,
                          reinterpret_cast<PBYTE>(&cng_key_usages),
                          sizeof(cng_key_usages),
                          &received_bytes,
                          0);

    if (security_status != ERROR_SUCCESS ||
        received_bytes != sizeof(cng_key_usages)) {
      return 0;
    }

    if ((cng_key_usages & cng_desired_key_usages) == cng_desired_key_usages) {
      return 1;
    }
  }

  // OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS for RSA keys doesn't exist,
  // so it's fine to return 1.
  // OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS is just something generic,
  // so we return always 1.
  return 1;
}

int OsqueryCNGKeyManagementExport(const void* key_data,
                                  int selection,
                                  OSSL_CALLBACK* param_callback,
                                  void* callback_arg) {
  const osquery::ProviderKey* provider_key =
      static_cast<const osquery::ProviderKey*>(key_data);

  OSSL_PARAM* param = nullptr;

  DBGERR("Attempting to export key at handle "
         << std::hex << provider_key->getHandle() << " with selection "
         << selection << std::dec);

  if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
    // We don't want to export the private key
    return 0;
  }

  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    DWORD public_blob_expected_size;
    SECURITY_STATUS security_status =
        NCryptExportKey(provider_key->getHandle(),
                        0,
                        BCRYPT_RSAPUBLIC_BLOB,
                        nullptr,
                        nullptr,
                        0,
                        &public_blob_expected_size,
                        0);
    if (security_status != ERROR_SUCCESS) {
      return 0;
    }

    if (public_blob_expected_size < sizeof(BCRYPT_RSAKEY_BLOB)) {
      return 0;
    }

    DWORD public_blob_size;
    std::vector<BYTE> public_key_blob(public_blob_expected_size);

    security_status = NCryptExportKey(provider_key->getHandle(),
                                      0,
                                      BCRYPT_RSAPUBLIC_BLOB,
                                      nullptr,
                                      public_key_blob.data(),
                                      public_blob_expected_size,
                                      &public_blob_size,
                                      0);
    if (security_status != ERROR_SUCCESS ||
        public_blob_expected_size != public_blob_size) {
      return 0;
    }

    BCRYPT_RSAKEY_BLOB rsa_key_header;
    std::size_t blob_offset = 0;

    std::memcpy(
        &rsa_key_header, &public_key_blob[blob_offset], sizeof(rsa_key_header));

    blob_offset += sizeof(rsa_key_header);

    if (blob_offset + rsa_key_header.cbPublicExp + rsa_key_header.cbModulus >
        public_blob_size) {
      return 0;
    }

    /*
      The endianness of CNG is opposite to what OpenSSL uses, reverse it first
     */
    std::vector<BYTE> rsa_public_expontent(rsa_key_header.cbPublicExp);
    std::memcpy(rsa_public_expontent.data(),
                &public_key_blob[blob_offset],
                rsa_public_expontent.size());
    std::reverse(rsa_public_expontent.begin(), rsa_public_expontent.end());

    blob_offset += rsa_public_expontent.size();

    std::vector<BYTE> rsa_public_modulus(rsa_key_header.cbModulus);
    std::memcpy(rsa_public_modulus.data(),
                &public_key_blob[blob_offset],
                rsa_public_modulus.size());
    std::reverse(rsa_public_modulus.begin(), rsa_public_modulus.end());

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
                                        rsa_public_expontent.data(),
                                        rsa_key_header.cbPublicExp);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N,
                                        rsa_public_modulus.data(),
                                        rsa_key_header.cbModulus);
    params[2] = OSSL_PARAM_construct_end();
    param = params;

    DBGERR("Successful export of key at handle: "
           << std::hex << provider_key->getHandle() << " with selection "
           << selection << std::dec);

    /* NOTE: we return here because this is the only type of selection
       we support now */
    return param_callback(param, callback_arg);
  }

  /*
    Here we should never arrive if the function has to be successful,
    but these are a couple of other examples of selections that we could
    be asked for.
    RSA keys don't have the domain parameter.

  if (selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) {
    return 0;
  }

  if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) {
    return 0;
  }*/

  return 0;
}

const OSSL_PARAM* OsqueryCNGKeyManagementExportTypes(int selection) {
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    static const OSSL_PARAM export_param_table[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
        OSSL_PARAM_END};
    return export_param_table;
  } else {
    return nullptr;
  }
}

const OSSL_PARAM* OsqueryCNGKeyManagementImportTypes(int selection) {
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    static const OSSL_PARAM import_param_table[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, nullptr, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, nullptr, 0),
        OSSL_PARAM_END};
    return import_param_table;
  } else {
    return nullptr;
  }
}

/*
  Imports a public key into our key management in an ephemeral way.
  This is needed when openssl receives a peer certificate through TLS
  communication, which is in the openssl built-in format, and want to convert it
  in our provider form, so that it can later use it with our functions.

  TODO: This import function for now is RSA specific.
*/
int OsqueryCNGKeyManagementImport(void* key_data,
                                  int selection,
                                  const OSSL_PARAM params[]) {
  if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
    const OSSL_PARAM* rsa_e =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    const OSSL_PARAM* rsa_n =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);

    if (rsa_e == nullptr || rsa_n == nullptr) {
      return 0;
    }

    BIGNUM* bn_rsa_n = nullptr;
    auto res = OSSL_PARAM_get_BN(rsa_n, &bn_rsa_n);

    if (res == 0) {
      return 0;
    }

    BIGNUM* bn_rsa_e = nullptr;
    res = OSSL_PARAM_get_BN(rsa_e, &bn_rsa_e);

    if (res == 0) {
      return 0;
    }

    NCRYPT_PROV_HANDLE prov_handle;
    auto security_status =
        NCryptOpenStorageProvider(&prov_handle, MS_KEY_STORAGE_PROVIDER, 0);

    if (security_status != ERROR_SUCCESS) {
      return 0;
    }

    BCRYPT_RSAKEY_BLOB blob{};

    blob.Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob.BitLength = BN_num_bits(bn_rsa_n);
    blob.cbModulus = static_cast<ULONG>(rsa_n->data_size);
    blob.cbPublicExp = static_cast<ULONG>(rsa_e->data_size);

    std::vector<BYTE> rsa_key(sizeof(BCRYPT_RSAKEY_BLOB) + blob.cbModulus +
                              blob.cbPublicExp);

    std::memcpy(rsa_key.data(), &blob, sizeof(blob));
    auto index = sizeof(blob);
    res = BN_bn2binpad(bn_rsa_e, &rsa_key[index], blob.cbPublicExp);

    if (res == -1) {
      NCryptFreeObject(prov_handle);
      return 0;
    }

    index += blob.cbPublicExp;
    res = BN_bn2binpad(bn_rsa_n, &rsa_key[index], blob.cbModulus);

    if (res == -1) {
      NCryptFreeObject(prov_handle);
      return 0;
    }

    osquery::ProviderKey* provider_key =
        static_cast<osquery::ProviderKey*>(key_data);
    NCRYPT_KEY_HANDLE handle;

    security_status = NCryptImportKey(prov_handle,
                                      0,
                                      BCRYPT_RSAPUBLIC_BLOB,
                                      nullptr,
                                      &handle,
                                      reinterpret_cast<PBYTE>(rsa_key.data()),
                                      static_cast<DWORD>(rsa_key.size()),
                                      NCRYPT_SILENT_FLAG);

    if (security_status != ERROR_SUCCESS) {
      DBGERR("Failed to import a key, error " << std::hex << security_status
                                              << std::dec);
      return 0;
    }

    *provider_key = osquery::ProviderKey(handle,
                                         osquery::ProviderKeyType::Public,
                                         osquery::ProviderKeyAlgorithm::RSA);

    NCryptFreeObject(prov_handle);
    return 1;
  }

  return 0;
}

void* OsqueryCNGKeyManagementDup(const void* keydata_from,
                                 [[maybe_unused]] int selection) {
  const osquery::ProviderKey* old_key_data =
      static_cast<const osquery::ProviderKey*>(keydata_from);

  auto* new_key_data = old_key_data->clone();

  if (new_key_data == nullptr) {
    DBGERR("Failed to duplicate key handle "
           << std::hex << old_key_data->getHandle() << std::dec);
    return nullptr;
  }

  DBGERR("Duplicated key handle " << std::hex << old_key_data->getHandle()
                                  << " to " << new_key_data->getHandle()
                                  << std::dec);

  return new_key_data;
}

const OSSL_ALGORITHM* OsqueryGetKeyManagementAlgorithms() {
  static const OSSL_ALGORITHM key_management_algorithms[]{
      {"rsaEncryption",
       osquery::algorithm_properties,
       osquery::key_management_functions,
       "RSA Implementation backed by Windows CNG"},
      {nullptr, nullptr, nullptr}};

  return key_management_algorithms;
}
