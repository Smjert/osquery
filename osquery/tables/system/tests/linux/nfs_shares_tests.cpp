/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/tables/system/linux/nfs_shares.h>

namespace osquery {
namespace tables {

class NFSSharesTests : public testing::Test {};

TEST_F(NFSSharesTests, test_empty_string) {
  std::string content;

  ExportFsParser parser(content);
  ASSERT_FALSE(parser.hasData());

  EXPECT_FALSE(parser.parseExportLine().has_value());
}

TEST_F(NFSSharesTests, test_comment) {
  std::string content = "# This is a comment";

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  EXPECT_FALSE(parser.parseExportLine().has_value());
}

TEST_F(NFSSharesTests, test_simple_export) {
  std::string content = "# This is a comment\n/";

  QueryData expected_results = {Row{{"share", "/"}, {"readonly", "1"}}};

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_simple_export_with_an_option) {
  std::string content = "# This is a comment\n/ 127.0.0.1";

  QueryData expected_results = {
      Row{{"share", "/"}, {"network", "127.0.0.1"}, {"readonly", "1"}}};

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_simple_export_with_options) {
  std::string content = "# This is a comment\n/ 127.0.0.1 host(rw)";

  // clang-format off
  QueryData expected_results = {
      Row{{"share", "/"}, {"network", "127.0.0.1"}, {"readonly", "1"}},
      Row{{"share", "/"}, {"network", "host"}, {"options", "rw"}, {"readonly", "0"}}};
  // clang-format on

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_simple_export_with_multiline_options) {
  std::string content =
      "# This is a comment\n/ 127.0.0.1 host(rw)\\\nmultiline_host";

  // clang-format off
  QueryData expected_results = {
      Row{{"share", "/"}, {"network", "127.0.0.1"}, {"readonly", "1"}},
      Row{{"share", "/"}, {"network", "host"}, {"options", "rw"}, {"readonly", "0"}},
      Row{{"share", "/"}, {"network", "multiline_host"}, {"readonly", "1"}}};
  // clang-format on

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_multiple_exports) {
  std::string content = "/ 127.0.0.1(rw)\\\n localhost(ro)\n/home 127.0.0.1";

  // clang-format off
  QueryData expected_results = {
    Row{{"share", "/"}, {"network", "127.0.0.1"}, {"options", "rw"}, {"readonly", "0"}},
    Row{{"share", "/"}, {"network", "localhost"}, {"options", "ro"}, {"readonly", "1"}},
  };
  // clang-format on

  ExportFsParser parser(content);

  // Parse first export line
  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);

  // Parse second export line
  expected_results = {
      Row{{"share", "/home"}, {"network", "127.0.0.1"}, {"readonly", "1"}}};

  opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_global_option) {
  std::string content = "/ -ro";

  QueryData expected_results = {
      Row{{"share", "/"}, {"options", "-ro"}, {"readonly", "1"}},
  };

  ExportFsParser parser(content);

  // Parse first export line
  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_multiple_global_options) {
  std::string content = "/ -ro -rw";

  QueryData expected_results = {
      Row{{"share", "/"}, {"options", "-ro"}, {"readonly", "1"}},
  };

  ExportFsParser parser(content);

  // Parse first export line
  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_multiple_global_options_with_networks) {
  std::string content = "/ -ro 127.0.0.1 -rw localhost";

  QueryData expected_results = {
      Row{{"share", "/"},
          {"network", "127.0.0.1"},
          {"options", "-ro"},
          {"readonly", "1"}},
      Row{{"share", "/"},
          {"network", "localhost"},
          {"options", "-rw"},
          {"readonly", "0"}},
  };

  ExportFsParser parser(content);

  // Parse first export line
  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests,
       test_multiple_global_options_with_networks_with_options) {
  std::string content = "/ -ro 127.0.0.1(rw) -rw localhost(ro)";

  QueryData expected_results = {
      Row{{"share", "/"},
          {"network", "127.0.0.1"},
          {"options", "-ro rw"},
          {"readonly", "0"}},
      Row{{"share", "/"},
          {"network", "localhost"},
          {"options", "-rw ro"},
          {"readonly", "1"}},
  };

  ExportFsParser parser(content);

  // Parse first export line
  auto opt_export = parser.parseExportLine();
  ASSERT_TRUE(opt_export.has_value());

  auto opt_export_rows = parser.convertExportToRows(*opt_export);
  ASSERT_TRUE(opt_export_rows.has_value());

  EXPECT_EQ(expected_results, *opt_export_rows);
}

TEST_F(NFSSharesTests, test_erroneous_inline_comment) {
  std::string content = "/ # This is a comment 127.0.0.1";

  ExportFsParser parser(content);

  EXPECT_FALSE(parser.parseExportLine().has_value());
}

TEST_F(NFSSharesTests, test_erroneously_quoted_export_path) {
  std::string content = "\"/";

  ExportFsParser parser(content);

  EXPECT_FALSE(parser.parseExportLine().has_value());
}

TEST_F(NFSSharesTests, test_erroneous_network_options) {
  std::string content = "/ 127.0.0.1(";

  ExportFsParser parser(content);

  auto opt_export = parser.parseExportLine();

  ASSERT_TRUE(opt_export.has_value());
  EXPECT_FALSE(parser.convertExportToRows(*opt_export).has_value());
}

} // namespace tables
} // namespace osquery
