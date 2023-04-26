#include <string_view>

#include <osquery/tables/system/linux/nfs_shares.h>

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view exportfs_content(reinterpret_cast<const char*>(data),
                                          size);

  osquery::tables::ExportFsParser parser(exportfs_content);

  while (parser.hasData()) {
    parser.parseExportLine();
  }

  return 0;
}
