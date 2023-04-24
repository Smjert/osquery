/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/conversions/trim.h>

namespace osquery {
namespace tables {

enum class ParserState { ExportPath, Options };

boost::optional<std::string> extractExportPath(
    std::string_view& remaining_string) {
  std::string_view export_path(remaining_string);

  int chars_processed = 0;

  /* An export path can start with a ", if it contains a whitespace,
     or immediately start with / */
  bool is_quoted = false;
  if (export_path[0] != '/') {
    if (export_path[0] != '"' || export_path.size() < 2 ||
        export_path[1] != '/') {
      VLOG(1) << "Malformed exportfs line, ignoring: " << export_path;
      return boost::none;
    }

    is_quoted = true;
  }

  if (is_quoted) {
    export_path.remove_prefix(1);
    auto end_quote_pos = export_path.find("\"");

    if (end_quote_pos == std::string_view::npos) {
      VLOG(1)
          << "Malformed exportfs line, could not find closing quote, ignoring: "
          << export_path;
      return boost::none;
    }

    // Start and end quotes
    ++chars_processed += 2;
    export_path.remove_suffix(export_path.size() - end_quote_pos);
  } else {
    auto space_pos = export_path.find(" ");

    if (space_pos != std::string_view::npos) {
      export_path.remove_suffix(export_path.size() - space_pos);
    }
  }

  chars_processed += export_path.size();
  remaining_string.remove_prefix(chars_processed);

  return std::string{export_path};
}

std::string isReadOnly(const std::string& options) {
    return "0";
}

QueryData genNFSShares(QueryContext& context) {
  QueryData results;

  std::string content;
  auto status = readFile("/etc/exports", content);
  if (!status.ok()) {
    VLOG(1) << "Error reading /etc/exports: " << status.toString();
    return {};
  }

  /* TODO:
    1. Check if a line can start with whitespaces
    2. Support multine configuration (on Linux is supported when lines finishes
       with \)
    3. Verify if a whitespace before then multiline \ is needed and if it still
       works if there's a whitespace after.

     ANSWER:
     1. A line can start with a whitespace or tabs
     3. Works if there's a whitespace before the \ or no whitespace, but it does
    not work if there's a whitespace after, because at that point it becomes an
    escape for the whitespace.
  */

  const auto lines = osquery::vsplit(content, '\n');

  std::string options;
  ParserState parser_state{};
  Row r;
  for (auto share_line : lines) {
    if (share_line.empty()) {
      continue;
    }

    // Lines can start with any number of whitespaces
    osquery::trimLeftInPlace(share_line);

    // And be empty, or start with a comment; so we skip them.
    if (share_line.empty() || share_line[0] == '#') {
      continue;
    }

    if (parser_state == ParserState::ExportPath) {
      auto opt_export_path = extractExportPath(share_line);

      if (!opt_export_path.has_value()) {
        continue;
      }

      r["share"] = std::move(*opt_export_path);

      // No options; the line might have a whitespace left
      if (share_line.size() < 2) {
        results.emplace_back(r);
        continue;
      }

      parser_state = ParserState::Options;
    }

    if (parser_state == ParserState::Options) {
      if (share_line.back() != '\\') {
        if (options.empty()) {
          options += share_line;
        } else {
          options += " ";
          options += share_line;
        }

        r["readonly"] = isReadOnly(options);
        r["options"] = std::move(options);
        options.clear();
        results.emplace_back(r);

        parser_state = ParserState::ExportPath;
        continue;
      }

      // Options continue on the next line, ignore escaping
      share_line.remove_suffix(1);
      options += share_line;
    }
  }
  return results;
}
} // namespace tables
} // namespace osquery
