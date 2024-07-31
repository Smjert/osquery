# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryUtilsOpenSSLMain)
  if(DEFINED PLATFORM_WINDOWS)
    add_subdirectory("windows")
  elseif(DEFINED PLATFORM_MACOS)
    add_subdirectory("darwin")
  endif()

  generateOsqueryUtilsOpenSSLUtils()
endfunction()

function(generateOsqueryUtilsOpenSSLUtils)
  set(sources 
    rsa_utils.cpp
    openssl_utils.cpp
  )

  if(DEFINED PLATFORM_WINDOWS)
    list(APPEND sources
      windows/openssl_utils.cpp
    )
  elseif(DEFINED PLATFORM_MACOS)
    list(APPEND sources
      darwin/openssl_utils.cpp
    )
  endif()

  add_osquery_library(osquery_utils_openssl_utils
    ${sources}
  )

  if (DEFINED PLATFORM_WINDOWS)
    target_link_libraries(osquery_utils_openssl_utils
      cxx_settings
      osquery_utils_openssl_cngprovider
      osquery_utils_expected
      thirdparty_openssl
    )
  elseif(DEFINED PLATFORM_MACOS)
    target_link_libraries(osquery_utils_openssl_utils
      cxx_settings
      osquery_utils_openssl_keychainprovider
      thirdparty_openssl
    )
  endif()

  set(public_header_files
    openssl_utils.h
    rsa_utils.h
  )

  generateIncludeNamespace(osquery_utils_openssl_utils "osquery/utils/openssl" "FILE_ONLY" ${public_header_files})
endfunction()

osqueryUtilsOpenSSLMain()
