# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(pluginsLoggerTestsMain)
  if(OSQUERY_BUILD_AWS)
    generatePluginsLoggerTestsAwskinesisloggertestsTest()
  endif()
  generatePluginsLoggerTestsFilesystemloggertestsTest()
  generatePluginsLoggerTestsBufferedloggertestsTest()
  generatePluginsLoggerTestsKafkaproducerloggertestsTest()
  generatePluginsLoggerTestsTlsloggertestsTest()

  if(DEFINED PLATFORM_POSIX)
    generatePluginsLoggerTestsSyslogloggertestsTest()
  endif()
endfunction()

function(generatePluginsLoggerTestsFilesystemloggertestsTest)
  add_osquery_executable(plugins_logger_tests_filesystemloggertests-test
    filesystem_logger_tests.cpp
    logrotate_tests.cpp
  )

  target_link_libraries(plugins_logger_tests_filesystemloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_sdk_emptyregisterforeigntables
    osquery_utils_conversions
    osquery_utils_info
    osquery_utils_system_time
    plugins_logger_filesystemlogger
    thirdparty_googletest
    thirdparty_boost
  )
endfunction()

function(generatePluginsLoggerTestsBufferedloggertestsTest)
  add_osquery_executable(plugins_logger_tests_bufferedloggertests-test buffered_tests.cpp)

  target_link_libraries(plugins_logger_tests_bufferedloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_dispatcher
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_sdk_emptyregisterforeigntables
    osquery_utils_info
    osquery_utils_json
    osquery_utils_system_time
    plugins_logger_buffered
    tests_helper
    thirdparty_googletest
    thirdparty_boost
  )
endfunction()

function(generatePluginsLoggerTestsKafkaproducerloggertestsTest)
  add_osquery_executable(plugins_logger_tests_kafkaproducerloggertests-test kafka_producer_tests.cpp)

  target_link_libraries(plugins_logger_tests_kafkaproducerloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions_implthrift
    osquery_registry
    osquery_sdk_emptyregisterforeigntables
    osquery_utils_status
    plugins_logger_kafkaproducer
    thirdparty_googletest
    thirdparty_boost
  )
endfunction()

function(generatePluginsLoggerTestsAwskinesisloggertestsTest)
  add_osquery_executable(plugins_logger_tests_awskinesisloggertests-test aws_kinesis_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_awskinesisloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_sdk_emptyregisterforeigntables
    plugins_logger_awskinesis
    thirdparty_googletest
    thirdparty_boost
  )
endfunction()

function(generatePluginsLoggerTestsTlsloggertestsTest)
  add_osquery_executable(plugins_logger_tests_tlsloggertests-test tls_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_tlsloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_database
    osquery_extensions_implthrift
    osquery_logger_datalogger
    osquery_registry
    osquery_remote_tests_remotetestutils
    osquery_sdk_emptyregisterforeigntables
    plugins_logger_tlslogger
    thirdparty_googletest
  )
endfunction()

function(generatePluginsLoggerTestsSyslogloggertestsTest)
  add_osquery_executable(plugins_logger_tests_syslogloggertests-test syslog_logger_tests.cpp)

  target_link_libraries(plugins_logger_tests_syslogloggertests-test PRIVATE
    osquery_cxx_settings
    osquery_core
    osquery_extensions_implthrift
    osquery_logger
    osquery_registry
    osquery_sdk_emptyregisterforeigntables
    plugins_logger_syslog
    thirdparty_googletest
  )
endfunction()

pluginsLoggerTestsMain()
