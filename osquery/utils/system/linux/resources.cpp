#include <osquery/utils/system/resources.h>

#include <charconv>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

#include <osquery/utils/conversions/trim.h>

namespace osquery {

namespace {
const std::string kProcfsPath = "/proc/";
const std::string kProcStatus = "/status";
const std::string kProcStatusVmSwapField = "VmSwap:";
const std::string kProcStatusVmRSSField = "VmRSS:";

constexpr std::size_t kProcStatusKBSuffixSize = 3;

std::optional<std::uint64_t> extractValue(std::string_view input) {
  // The line is malformed if there aren't enough characters
  // for the suffix and at least one digit.
  if (input.size() < (kProcStatusKBSuffixSize + 1)) {
    return std::nullopt;
  }

  // The line should end with a suffix we want to skip
  auto value_end_pos = input.size() - 1 - kProcStatusKBSuffixSize;

  std::string_view value_line(&input[0], value_end_pos + 1);
  value_line = osquery::ltrim(value_line);

  std::uint64_t value;
  auto [ptr, ec] = std::from_chars(
      value_line.data(), value_line.data() + value_line.size(), value, 10);

  if (ec != std::errc()) {
    return std::nullopt;
  }

  return {value};
}
} // namespace

Expected<std::uint64_t, ResourceError> getProcessTotalMemoryUsage(
    const std::uint32_t process_id) {
  using ProcExpected = Expected<std::uint64_t, ResourceError>;

  std::string proc_status_path =
      kProcfsPath + std::to_string(process_id) + kProcStatus;
  std::ifstream proc_status(proc_status_path);

  if (!proc_status.is_open()) {
    return ProcExpected::failure(ResourceError::GenericError,
                                 "Failed to open " + proc_status_path);
  }

  std::uint64_t swap = 0;
  std::uint64_t rss = 0;
  std::string line;
  while (std::getline(proc_status, line)) {
    // std::cout << "STATUS: " << line << std::endl;
    if (line.compare(
            0, kProcStatusVmSwapField.size(), kProcStatusVmSwapField) == 0) {
      std::string_view line_view(&line[kProcStatusVmSwapField.size()],
                                 line.size() - kProcStatusVmSwapField.size());
      auto opt_result = extractValue(line_view);

      if (!opt_result.has_value()) {
        return ProcExpected::failure(ResourceError::GenericError,
                                     "Failed to extract the VmSwap value");
      }

      swap = *opt_result * 1024;
    } else if (line.compare(0,
                            kProcStatusVmRSSField.size(),
                            kProcStatusVmRSSField) == 0) {
      std::string_view line_view(&line[kProcStatusVmRSSField.size()],
                                 line.size() - kProcStatusVmRSSField.size());

      std::cout << "LINE_VIEW: " << std::string(line_view) << std::endl;

      auto opt_result = extractValue(line_view);

      if (!opt_result.has_value()) {
        return ProcExpected::failure(ResourceError::GenericError,
                                     "Failed to extract the VmRSS value");
      }

      rss = *opt_result * 1024;
      break;
    }
  }

  return rss + swap;
}
} // namespace osquery
