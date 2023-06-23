#pragma once

#include <string>
#include <string_view>

#include <boost/optional.hpp>

#include <osquery/core/sql/row.h>
#include <osquery/core/tables.h>

namespace osquery {
namespace tables {
enum class ParserState { ExportPath, Options };

struct Export {
  std::string path;
  std::string options;
};

class ExportFsParser {
 public:
  ExportFsParser(std::string_view content) : remaining_content_(content) {}

  /**
   * @brief Parses one export config "line", including multiline options
   * @return Export path and options if there are no parsing errors
   *
   * Parses one export config "line", including multiline options.
   * It does some validation of what's parsing, given how the real parser
   * behaves, but it only does so if the result may become ambiguos or clearly
   * broken. There are other cases that it will not check, since it's not meant
   * to be a 1:1 parser with the real one.
   */
  boost::optional<Export> parseExportLine();

  /**
   * @brief Converts export path and options to table rows
   * @return Table rows if there are no parsing errors
   *
   * Converts export path and options to table rows; for each host in the
   * options, a new row is created which will use the same share path. It tries
   * to do some minimal validation like parseExportLine.
   */
  boost::optional<QueryData> convertExportToRows(const Export& share);

  bool hasData() {
    return !remaining_content_.empty();
  }

  std::size_t getCurrentLineNumber() {
    return line_number_;
  }

 private:
  ParserState parser_state_{};
  std::string_view remaining_content_;
  std::string export_path_;
  std::string options_;
  std::size_t line_number_{};
};
} // namespace tables
} // namespace osquery
