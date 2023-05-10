#pragma once

#include <string>
#include <string_view>

#include <boost/optional.hpp>

#include <osquery/core/sql/row.h>

namespace osquery {
namespace tables {
enum class ParserState { ExportPath, Options };

class ExportFsParser {
 public:
  ExportFsParser(std::string_view content) : remaining_content(content) {}
  boost::optional<Row> parseExportLine();

  bool hasData() {
    return !remaining_content.empty();
  }

  bool hasParsingErrors() {
    return has_parsing_errors;
  }

 private:
  /* void processExportLine(std::size_t line_number, std::string_view&
   * remaining_line, Row& r);*/

  ParserState parser_state{};
  std::string_view remaining_content;
  std::string export_path;
  std::string options;
  std::size_t newline_pos{};
  std::size_t line_number{};
  bool has_parsing_errors{};
};
} // namespace tables
} // namespace osquery
