# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(osqueryRemoteTestsMain)
  generateOsqueryRemoteTestsRemotetestsutils()
  generateOsqueryRemoteTestsRequeststestsTest()
endfunction()

function(generateOsqueryRemoteTestsRemotetestsutils)
  add_osquery_library(osquery_remote_tests_remotetestutils EXCLUDE_FROM_ALL test_utils.cpp)

  set(public_header_files
    test_utils.h
  )

  generateIncludeNamespace(osquery_remote_tests_remotetestutils "osquery/remote/tests" "FILE_ONLY" ${public_header_files})

  target_link_libraries(osquery_remote_tests_remotetestutils PUBLIC
    osquery_cxx_settings
    osquery_core
    osquery_config_tests_testutils
    osquery_database
    osquery_extensions_implthrift
    osquery_logger
    osquery_sql
    specs_tables
    osquery_utils_conversions
    osquery_utils_info
    tests_helper
  )
endfunction()

function(generateOsqueryRemoteTestsRequeststestsTest)
  add_osquery_executable(osquery_remote_tests_requeststests-test requests_tests.cpp)

  target_link_libraries(osquery_remote_tests_requeststests-test PRIVATE
    osquery_cxx_settings
    osquery_extensions_implthrift
    osquery_remote_transports_transportstls
    osquery_remote_serializers_serializerjson
    osquery_sdk_emptyregisterforeigntables
    osquery_utils_conversions
    thirdparty_googletest
  )
endfunction()

osqueryRemoteTestsMain()
