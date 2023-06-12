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
  ExportFsParser(std::string_view content) : remaining_content(content) {}
  boost::optional<Export> parseExportLine();
  boost::optional<QueryData> convertExportToRows(const Export& share);

  bool hasData() {
    return !remaining_content.empty();
  }

  std::size_t getCurrentLineNumber() {
    return line_number;
  }

 private:
  ParserState parser_state{};
  std::string_view remaining_content;
  std::string export_path;
  std::string options;
  std::size_t line_number{};
};
} // namespace tables
} // namespace osquery
