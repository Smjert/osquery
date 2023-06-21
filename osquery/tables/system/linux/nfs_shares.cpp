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

enum class AccessType { ReadOnlyDefault, ReadOnly, Write };

namespace {
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

    // Extract export path between quotes
    export_path = remaining_line.substr(1, end_quote_pos - 1);

    // Consume the parsed export_path with quotes
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

AccessType getAccessType(const std::string_view options_string) {
  auto options = osquery::vsplit(options_string, ',');

  for (auto option : options) {
    option = osquery::trim(option);

    if (option == "rw") {
      return AccessType::Write;
    }

    if (option == "ro") {
      return AccessType::ReadOnly;
    }
  }

  return AccessType::ReadOnlyDefault;
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
} // namespace

boost::optional<QueryData> ExportFsParser::convertExportToRows(
    const Export& share) {
  if (share.options.empty()) {
    Row r;
    r["share"] = std::move(share.path);
    r["readonly"] = "1"; // The export is read-only by default

    return QueryData{std::move(r)};
  }

  QueryData rows;

  auto options_groups = osquery::vsplit(share.options, ' ');

  // Trim all options and remove empty ones
  for (auto it = options_groups.begin(); it != options_groups.end(); ++it) {
    auto options_group = osquery::trim(*it);

    if (options_group.empty()) {
      it = options_groups.erase(it);
    } else {
      *it = options_group;
    }
  }

  bool is_writable_global = false;
  bool found_global_options = false;

  std::string global_options;

  for (std::size_t i = 0; i < options_groups.size(); ++i) {
    auto options_group = options_groups[i];

    Row r;
    r["share"] = share.path;

    // Global options can appear multiple times and they apply to whatever comes
    // after them, up to the next set of global options, if any.
    if (options_group[0] == '-') {
      // This is a bit of an idiosincrasy of the real parser, but if there are
      // multiple sets of global options, one after the other, only the first
      // will actually be considered
      if (found_global_options) {
        continue;
      }

      found_global_options = true;

      global_options = options_group;

      is_writable_global =
          getAccessType(options_group.substr(1)) == AccessType::Write;

      // If the last option group we parse are global options,
      // we want to create a row for them immediately, and return the generated
      // rows.

      if (i == options_groups.size() - 1) {
        r["readonly"] = is_writable_global ? "0" : "1";
        r["options"] = global_options;
        rows.emplace_back(std::move(r));
        return rows;
      }

      continue;
    }

    found_global_options = false;

    auto open_parens = options_group.find("(");
    if (open_parens != std::string_view::npos) {
      auto close_parens = options_group.find(")");

      if (close_parens == std::string_view::npos) {
        VLOG(1)
            << "Could not find closing parens for the options in option group: "
            << options_group << " at line " << line_number;
        return boost::none;
      }

      auto options_length = close_parens - (open_parens + 1);
      if (options_length == 0) {
        // No options within parens for a network are supported
        r["readonly"] = "1";
        rows.emplace_back(std::move(r));
        continue;
      }

      auto host_options = options_group.substr(open_parens + 1, options_length);
      auto access_type = getAccessType(options);

      bool readOnly = is_writable_global ? access_type == AccessType::ReadOnly
                                         : access_type != AccessType::Write;

      r["options"] = global_options.empty() ? options
                                            : std::string(global_options) +
                                                  " " + std::string(options);
      r["network"] = std::string(options_group.data(), open_parens);
      r["readonly"] = readOnly ? "1" : "0";
    } else {
      // Assume this is the host
      r["network"] = options_group;
      r["readonly"] = is_writable_global ? "0" : "1";
      if (!global_options.empty()) {
        r["options"] = global_options;
      }
    }

    rows.emplace_back(std::move(r));
  }

  return rows;
}

boost::optional<Export> ExportFsParser::parseExportLine() {
  std::string_view remaining_line;
  Export share;

  do {
    remaining_line = extractAndConsumeLine(remaining_content);
    ++line_number;
    osquery::trimLeftInPlace(remaining_line);

    while (!remaining_line.empty()) {
      if (parser_state == ParserState::ExportPath) {
        // Skip comments
        if (remaining_line[0] == '#') {
          remaining_line = {};
          continue;
        }

        auto opt_export_path = extractAndConsumeExportPath(remaining_line);
        if (!opt_export_path.has_value()) {
          VLOG(1) << "Malformed exportfs export path at line " << line_number
                  << ", ignoring";
          remaining_line = {};
          return boost::none;
        }

        export_path = std::move(*opt_export_path);
        parser_state = ParserState::Options;
      }

      if (parser_state == ParserState::Options) {
        osquery::trimLeftInPlace(remaining_line);

        // There were no options, return the export
        if (remaining_line.empty()) {
          share.path = std::move(export_path);
          parser_state = ParserState::ExportPath;
          return share;
        }

        /* A comment found in between the export path
           and the options is an error */
        if (remaining_line[0] == '#') {
          VLOG(1) << "Malformed exportfs options for path " << export_path
                  << " at line " << line_number
                  << ", comment in options continuation "
                     "line, ignoring";
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

          share.options = std::move(options);
          share.path = std::move(export_path);

          options.clear();
          export_path.clear();
          parser_state = ParserState::ExportPath;
          return share;
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

  bool had_errors = false;

  while (parser.hasData()) {
    auto opt_share = parser.parseExportLine();

    if (!opt_share.has_value()) {
      had_errors = true;
      continue;
    }

    auto opt_rows = parser.convertExportToRows(*opt_share);

    if (!opt_rows.has_value()) {
      had_errors = true;
      continue;
    }

    const auto& rows = *opt_rows;

    results.reserve(results.size() + rows.size());
    std::move(rows.begin(), rows.end(), std::back_inserter(results));
  }

  if (had_errors) {
    LOG(ERROR) << "Parsing of the export file had errors, results will be "
                  "incomplete";
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
