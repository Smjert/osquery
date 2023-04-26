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
    std::string_view& remaining_string) {
  std::string_view export_path(remaining_string);

  int chars_processed = 0;

  /* An export path can start with a ", if it contains a whitespace,
     or immediately start with / */
  bool is_quoted = false;
  if (export_path[0] != '/') {
    if (export_path[0] != '"' || export_path.size() < 2 ||
        export_path[1] != '/') {
      return boost::none;
    }

    is_quoted = true;
  }

  if (is_quoted) {
    export_path.remove_prefix(1);
    auto end_quote_pos = export_path.find("\"");

    if (end_quote_pos == std::string_view::npos) {
      return boost::none;
    }

    // Count start and end quotes
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

QueryData parseExportfs(const std::string& content) {
  const auto lines = osquery::vsplit(content, '\n');

  std::string options;
  std::string export_path;
  ParserState parser_state{};
  QueryData results;
  Row r;
  for (std::size_t line = 0; line < lines.size(); ++line) {
    std::string_view share_line(lines[line]);

    if (share_line.empty()) {
      continue;
    }

    // Lines can start with any number of whitespaces
    osquery::trimLeftInPlace(share_line);

    // And be empty so we skip them
    if (share_line.empty()) {
      continue;
    }

    std::size_t line_number = line + 1;

    /* Lines could also start with a comment,
       but not if they are a continuation line for options. */
    if (share_line[0] == '#') {
      if (parser_state == ParserState::Options) {
        VLOG(1) << "Malformed exportfs options for path " << export_path
                << " at line " << line_number
                << ", comment in options continuation "
                   "line, ignoring";

        // Also change the parser state to ExportPath,
        // so that it stops trying to parse options on a continuation line
        // and correctly errors out and skips also the subsequent line.
        parser_state = ParserState::ExportPath;
      }
      continue;
    }

    if (parser_state == ParserState::ExportPath) {
      auto opt_export_path = extractAndConsumeExportPath(share_line);

      if (!opt_export_path.has_value()) {
        VLOG(1) << "Malformed exportfs export path at line " << line_number
                << ", ignoring";
        continue;
      }

      export_path = std::move(*opt_export_path);

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
          /* These is a continuation line for options,
             normalize the whitespace separator*/
          osquery::trimLeftInPlace(share_line);
          options += " ";
          options += share_line;
        }

        r["readonly"] = isReadOnly(options);
        r["options"] = std::move(options);
        r["share"] = std::move(export_path);

        options.clear();
        export_path.clear();
        results.emplace_back(r);

        parser_state = ParserState::ExportPath;
        continue;
      }

      // Options continue on the next line, ignore escaping and whitespaces
      share_line.remove_suffix(1);
      // osquery::trimRightInPlace(share_line);

      options += share_line;
    }
  }
  return results;
}

void consumeLine(std::string_view& remaining_content) {
  auto line_size = remaining_content.find("\n");

  if (line_size == std::string_view::npos) {
    line_size = remaining_content.size();
  } else {
    ++line_size;
  }

  remaining_content.remove_prefix(remaining_content.size() - line_size);
}

std::string_view extractAndConsumeLine(std::string_view& remaining_content) {
  auto newline_pos = remaining_content.find("\n");

  if (newline_pos == std::string_view::npos) {
    remaining_content.remove_prefix(remaining_content.size());
    return {};
  }

  std::string_view line = remaining_content.substr(0, newline_pos);
  remaining_content.remove_prefix(newline_pos + 1);

  return line;
}

boost::optional<Row> ExportFsParser::parseExportLine() {
  std::string_view remaining_line;
  Row r;

  do {
    if (parser_state == ParserState::ExportPath) {
      remaining_line = extractAndConsumeLine(remaining_content);
      ++line_number;
      osquery::trimLeftInPlace(remaining_line);

      if (remaining_line.empty() || remaining_line[0] == '#') {
        continue;
      }

      auto opt_export_path = extractAndConsumeExportPath(remaining_line);

      if (!opt_export_path.has_value()) {
        VLOG(1) << "Malformed exportfs export path at line " << line_number
                << ", ignoring";
        has_parsing_errors = true;
        continue;
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

      if (remaining_line[0] == '#') {
        VLOG(1) << "Malformed exportfs options for path " << export_path
                << " at line " << line_number
                << ", comment in options continuation "
                   "line, ignoring";
        has_parsing_errors = true;
        parser_state = ParserState::ExportPath;
        return boost::none;
      }

      if (remaining_line.back() != '\\') {
        // End of options but no previous option line read
        if (options.empty()) {
          options += remaining_line;
        } else {
          // End of options, append to previous options
          options += " ";
          options += remaining_line;
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
        remaining_line = extractAndConsumeLine(remaining_content);
        ++line_number;
      }
    }
  } while (!remaining_content.empty());

  parser_state = ParserState::ExportPath;

  return boost::none;
}

QueryData parseExportfs2(const std::string& content) {
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

  return parseExportfs2(content);
}
} // namespace tables
} // namespace osquery
