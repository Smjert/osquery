# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsOpenSSLCngProviderMain)
  generateOsqueryUtilsOpenSSLCngProvider()
  generateOsqueryUtilsOpenSSLCngProviderTests()
endfunction()

function(generateOsqueryUtilsOpenSSLCngProvider)

  add_osquery_library(osquery_utils_openssl_cngprovider STATIC
    signature/signature.cpp
    keymanagement/key_management.cpp
    keymanagement/provider_key.cpp
    store/store.cpp
    cng.cpp
  )

  target_link_libraries(osquery_utils_openssl_cngprovider PUBLIC
    osquery_cxx_settings
    osquery_utils_conversions
    osquery_utils_openssl_utils
    thirdparty_openssl
  )

  if(OSQUERY_BUILD_TESTS)
    add_test(NAME osquery_utils_openssl_cngprovider_tests-test COMMAND osquery_utils_openssl_cngprovider_tests-test)
  endif()

  set(public_header_files
    cng.h
    common/provider_context.h
    common/defines.h
    signature/signature.h
    signature/signature_ctx.h
    keymanagement/key_management.h
    keymanagement/provider_key.h
    store/store.h
  )

  generateIncludeNamespace(osquery_utils_openssl_cngprovider "osquery/utils/openssl/windows/cng_provider" "FULL_PATH" ${public_header_files})
endfunction()

function(generateOsqueryUtilsOpenSSLCngProviderTests)
  
  add_osquery_executable(osquery_utils_openssl_cngprovider_tests-test
    tests/openssl_tests.cpp
  )

  target_link_libraries(osquery_utils_openssl_cngprovider_tests-test PRIVATE
    osquery_cxx_settings
    osquery_utils_openssl_cngprovider
    thirdparty_googletest
  )

  target_compile_definitions(osquery_utils_openssl_cngprovider_tests-test PRIVATE
    OSQUERY_PFX_PATH="${CMAKE_CURRENT_SOURCE_DIR}/tests/osquery.pfx"
  )
endfunction()

osqueryUtilsOpenSSLCngProviderMain()
