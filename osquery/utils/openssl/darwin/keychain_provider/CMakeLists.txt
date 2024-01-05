# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsOpenSSLDarwinKeychainProviderMain)
  generateOsqueryUtilsOpenSSLDarwinKeychainProvider()
endfunction()


function(generateOsqueryUtilsOpenSSLDarwinKeychainProvider)
  add_osquery_library(osquery_utils_openssl_keychainprovider
    keymanagement/key_management.cpp
    keymanagement/key_management.h
    keymanagement/provider_key.cpp
    keymanagement/provider_key.h
    signature/signature.cpp
    signature/signature.h
    signature/signature_ctx.h
    store/store.cpp
    store/store.h
    keychain.h
    keychain.cpp
  )

  target_link_libraries(osquery_utils_openssl_keychainprovider PRIVATE
    osquery_cxx_settings
    osquery_utils_openssl_utils
    thirdparty_openssl
  )

  set(public_header_files
    keychain.h
    common/provider_context.h
    common/defines.h
    signature/signature.h
    signature/signature_ctx.h
    keymanagement/key_management.h
    keymanagement/provider_key.h
    store/store.h
  )

  generateIncludeNamespace(osquery_utils_openssl_keychainprovider "osquery/utils/openssl/darwin/keychain_provider" "FULL_PATH" ${public_header_files})
endfunction()

osqueryUtilsOpenSSLDarwinKeychainProviderMain()
