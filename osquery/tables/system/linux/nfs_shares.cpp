/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "nfs_shares.h"

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

boost::optional<std::string> extractAndConsumeExportPath(
    std::string_view& remaining_line) {
  std::string_view export_path;

  /* An export path can start with a ", if it contains a whitespace,
     or immediately start with / */
  if (remaining_line[0] != '/') {
    if (remaining_line[0] != '"' || remaining_line.size() < 2 ||
        remaining_line[1] != '/') {
      return boost::none;
    }

    auto end_quote_pos = remaining_line.find("\"", 1);

    if (end_quote_pos == std::string_view::npos) {
      return boost::none;
    }

    export_path = remaining_line.substr(1, end_quote_pos - 1);
    remaining_line.remove_prefix(end_quote_pos + 1);
  } else {
    auto space_pos = remaining_line.find(" ");

    if (space_pos != std::string_view::npos) {
      export_path = remaining_line.substr(0, space_pos);
      remaining_line.remove_prefix(space_pos + 1);
    } else {
      export_path = remaining_line;
      remaining_line = {};
    }
  }

  return std::string{export_path};
}

boost::optional<std::string> isReadOnly(const std::string& options) {
  auto hosts = osquery::vsplit(options, ' ');

  for (const auto host : hosts) {
    auto open_paren_pos = host.find("(");

    if (open_paren_pos == std::string_view::npos) {
      continue;
    }

    auto close_paren_pos = host.find(")");

    if (open_paren_pos == std::string_view::npos) {
      return boost::none;
    }

    auto host_option_string =
        host.substr(open_paren_pos + 1, close_paren_pos - open_paren_pos);

    auto host_options = osquery::vsplit(options, ',');

    for (const auto host_option : host_options) {
      if (host_option == "ro") {
        return std::string{"1"};
      }
    }
  }

  return std::string{"0"};
}

std::string_view extractAndConsumeLine(std::string_view& remaining_content) {
  auto newline_pos = remaining_content.find("\n");

  if (newline_pos == std::string_view::npos) {
    std::string_view remaining_line = remaining_content;
    remaining_content = {};
    return remaining_line;
  }

  std::string_view line = remaining_content.substr(0, newline_pos);
  remaining_content.remove_prefix(newline_pos + 1);

  return line;
}

boost::optional<Row> ExportFsParser::parseExportLine() {
  std::string_view remaining_line;
  Row r;

  do {
    remaining_line = extractAndConsumeLine(remaining_content);
    ++line_number;
    osquery::trimLeftInPlace(remaining_line);

    while (!remaining_line.empty()) {
      if (parser_state == ParserState::ExportPath) {
        if (remaining_line[0] == '#') {
          remaining_line = {};
          continue;
        }

        auto opt_export_path = extractAndConsumeExportPath(remaining_line);
        if (!opt_export_path.has_value()) {
          VLOG(1) << "Malformed exportfs export path at line " << line_number
                  << ", ignoring";
          has_parsing_errors = true;
          remaining_line = {};
          return boost::none;
        }

        export_path = std::move(*opt_export_path);
        parser_state = ParserState::Options;
      }

      if (parser_state == ParserState::Options) {
        osquery::trimLeftInPlace(remaining_line);

        if (remaining_line.empty()) {
          r["readonly"] = "0";
          r["share"] = std::move(export_path);
          parser_state = ParserState::ExportPath;
          return r;
        }

        /* A comment found in between the export path
           and the options is an error */
        if (remaining_line[0] == '#') {
          VLOG(1) << "Malformed exportfs options for path " << export_path
                  << " at line " << line_number
                  << ", comment in options continuation "
                     "line, ignoring";
          has_parsing_errors = true;
          parser_state = ParserState::ExportPath;
          return boost::none;
        }

        // There could be a comment at the end of the line
        auto comment_pos = remaining_line.find('#');
        if (comment_pos != std::string_view::npos) {
          // Process only the part without the comment
          remaining_line = remaining_line.substr(0, comment_pos);
        }

        /* Options can be split on multiple lines; if there's no backspace
           end the export line */
        if (remaining_line.back() != '\\') {
          // End of options, but no previous option line read
          if (options.empty()) {
            options += remaining_line;
            remaining_line = {};
          } else {
            // End of options, append to previous options
            options += " ";
            options += remaining_line;
            remaining_line = {};
          }

          r["readonly"] = isReadOnly(options);
          r["options"] = std::move(options);
          r["share"] = std::move(export_path);

          options.clear();
          export_path.clear();
          parser_state = ParserState::ExportPath;
          return r;
        } else {
          remaining_line.remove_suffix(1);
          options += remaining_line;
          remaining_line = {};
        }
      }
    }
  } while (!remaining_content.empty());

  parser_state = ParserState::ExportPath;

  return boost::none;
}

QueryData parseExportfs(const std::string& content) {
  QueryData results;

  ExportFsParser parser(content);

  while (parser.hasData()) {
    auto opt_row = parser.parseExportLine();

    if (opt_row.has_value()) {
      results.emplace_back(std::move(*opt_row));
    }
  }

  return results;
}

QueryData genNFSShares(QueryContext& context) {
  std::string content;
  auto status = readFile("/etc/exports", content);
  if (!status.ok()) {
    VLOG(1) << "Error reading /etc/exports: " << status.toString();
    return {};
  }

  return parseExportfs(content);
}
} // namespace tables
} // namespace osquery
