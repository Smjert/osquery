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

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export_row = parser.parseExportLine();
  ASSERT_TRUE(opt_export_row.has_value());

  const auto& export_row = *opt_export_row;
  ASSERT_EQ(export_row.size(), 2);

  const auto share_it = export_row.find("share");
  ASSERT_NE(share_it, export_row.end());
  EXPECT_EQ(share_it->second, "/");

  const auto readonly_it = export_row.find("readonly");
  ASSERT_NE(readonly_it, export_row.end());
  EXPECT_EQ(readonly_it->second, "0");
}

TEST_F(NFSSharesTests, test_simple_export_with_an_option) {
  std::string content = "# This is a comment\n/ 127.0.0.1";

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export_row = parser.parseExportLine();
  ASSERT_TRUE(opt_export_row.has_value());

  const auto& export_row = *opt_export_row;
  ASSERT_EQ(export_row.size(), 3);

  const auto share_it = export_row.find("share");
  ASSERT_NE(share_it, export_row.end());
  EXPECT_EQ(share_it->second, "/");

  const auto readonly_it = export_row.find("readonly");
  ASSERT_NE(readonly_it, export_row.end());
  EXPECT_EQ(readonly_it->second, "0");

  const auto options_it = export_row.find("options");
  ASSERT_NE(options_it, export_row.end());
  EXPECT_EQ(options_it->second, "127.0.0.1");
}

TEST_F(NFSSharesTests, test_simple_export_with_options) {
  std::string content = "# This is a comment\n/ 127.0.0.1 host(rw)";
  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export_row = parser.parseExportLine();
  ASSERT_TRUE(opt_export_row.has_value());

  const auto& export_row = *opt_export_row;
  ASSERT_EQ(export_row.size(), 3);

  const auto share_it = export_row.find("share");
  ASSERT_NE(share_it, export_row.end());
  EXPECT_EQ(share_it->second, "/");

  const auto readonly_it = export_row.find("readonly");
  ASSERT_NE(readonly_it, export_row.end());
  EXPECT_EQ(readonly_it->second, "0");

  const auto options_it = export_row.find("options");
  ASSERT_NE(options_it, export_row.end());
  EXPECT_EQ(options_it->second, "127.0.0.1 host(rw)");
}

TEST_F(NFSSharesTests, test_simple_export_with_multiline_options) {
  std::string content =
      "# This is a comment\n/ 127.0.0.1 host(rw)\\\nmultiline_host";

  ExportFsParser parser(content);
  ASSERT_TRUE(parser.hasData());

  auto opt_export_row = parser.parseExportLine();
  ASSERT_TRUE(opt_export_row.has_value());

  const auto& export_row = *opt_export_row;
  ASSERT_EQ(export_row.size(), 3);

  const auto share_it = export_row.find("share");
  ASSERT_NE(share_it, export_row.end());
  EXPECT_EQ(share_it->second, "/");

  const auto readonly_it = export_row.find("readonly");
  ASSERT_NE(readonly_it, export_row.end());
  EXPECT_EQ(readonly_it->second, "0");

  const auto options_it = export_row.find("options");
  ASSERT_NE(options_it, export_row.end());
  EXPECT_EQ(options_it->second, "127.0.0.1 host(rw) multiline_host");
}

} // namespace tables
} // namespace osquery
