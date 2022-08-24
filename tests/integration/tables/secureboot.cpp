/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/tests/integration/tables/helper.h>
#include <osquery/utils/info/platform_type.h>

#include <Windows.h>

#include <DbgHelp.h>

#include <boost/format.hpp>

namespace osquery::table_tests {

class Secureboot : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

static std::string getStack(CONTEXT& context) {
  BOOL result;
  HANDLE process;
  HANDLE thread;
  STACKFRAME64 stack;
  constexpr std::uint32_t symbol_name_size = 1024;

  char symbol_mem[sizeof(IMAGEHLP_SYMBOL64) + symbol_name_size];
  IMAGEHLP_SYMBOL64* symbol = (IMAGEHLP_SYMBOL64*)symbol_mem;
  DWORD64 displacement;

  std::string name(symbol_name_size, '\0');
  std::string out;
  out += "Crash callstack:\n";
  memset(&stack, 0, sizeof(STACKFRAME64));

  process = GetCurrentProcess();
  thread = GetCurrentThread();
  displacement = 0;
  DWORD machineType;
#ifdef _WIN64
  machineType = IMAGE_FILE_MACHINE_IA64;
  stack.AddrPC.Offset = context.Rip;
  stack.AddrPC.Mode = AddrModeFlat;
  stack.AddrStack.Offset = context.Rsp;
  stack.AddrStack.Mode = AddrModeFlat;
  stack.AddrFrame.Offset = context.Rbp;
  stack.AddrFrame.Mode = AddrModeFlat;
#else
  machineType = IMAGE_FILE_MACHINE_I386;
  stack.AddrPC.Offset = context.Eip;
  stack.AddrPC.Mode = AddrModeFlat;
  stack.AddrStack.Offset = context.Esp;
  stack.AddrStack.Mode = AddrModeFlat;
  stack.AddrFrame.Offset = context.Ebp;
  stack.AddrFrame.Mode = AddrModeFlat;
#endif

  do {
    result = StackWalk64(machineType,
                         process,
                         thread,
                         &stack,
                         NULL,
                         //&context,
                         NULL,
                         SymFunctionTableAccess64,
                         SymGetModuleBase64,
                         NULL);

    symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
    symbol->MaxNameLength = symbol_name_size - 1;

    if (stack.AddrPC.Offset != 0) {
      SymGetSymFromAddr64(
          process, (ULONG64)stack.AddrPC.Offset, &displacement, symbol);
      // UnDecorateSymbolName(
      //     symbol->Name, (PSTR)&name[0], name.size(), UNDNAME_COMPLETE);

      IMAGEHLP_LINE64 line{};
      line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
      DWORD line_displacement = 0;
      auto res = SymGetLineFromAddr64(
          process, (ULONG64)stack.AddrPC.Offset, &line_displacement, &line);

      if (res) {
        out += line.FileName;
        out += '|';
      }

      out += symbol->Name;

      if (res) {
        out += std::to_string(line.LineNumber);
        out += ':';
        out += std::to_string(line_displacement);
      }
      
      out += '|';
      out += (boost::format("0x%x") % (ULONG64)stack.AddrPC.Offset).str();
      out += '+';
      out += (boost::format("0x%x") % displacement).str();

      out += '\n';
    }

  } while (result);

  return out;
}

static LONG WINAPI SEHFilterFunc(LPEXCEPTION_POINTERS exceptions) {
  VLOG(1) << __LINE__;
  std::cerr << "Error Code: " << exceptions->ExceptionRecord->ExceptionCode
            << std::endl;

  std::cerr << getStack(*exceptions->ContextRecord);

  return EXCEPTION_EXECUTE_HANDLER;
}

TEST_F(Secureboot, test_sanity) {
  bool secureboot_supported{false};

  static const auto result = SymInitialize(GetCurrentProcess(), nullptr, TRUE);

  ASSERT_TRUE(result);

  SetUnhandledExceptionFilter(SEHFilterFunc);

  {
    auto platform_info_rows =
        execute_query("SELECT firmware_type FROM platform_info;");

    ASSERT_EQ(platform_info_rows.size(), 1);

    const auto& platform_info = platform_info_rows[0];
    ASSERT_EQ(platform_info.count("firmware_type"), 1);

    secureboot_supported = platform_info.at("firmware_type") == "uefi";
  }

  auto secureboot_data = execute_query("SELECT * FROM secureboot;");
  if (!secureboot_supported) {
    ASSERT_TRUE(secureboot_data.empty());
    return;
  }

  ASSERT_EQ(secureboot_data.size(), 1);
  static const ValidationMap kValidationMap{
      {"secure_boot", IntOrEmpty},
      {"setup_mode", IntOrEmpty},
  };

  validate_rows(secureboot_data, kValidationMap);
}

} // namespace osquery::table_tests
