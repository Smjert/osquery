/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/system/secureboot.hpp>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/info/firmware.h>

#include <Windows.h>

#include <DbgHelp.h>

#include <boost/format.hpp>
#include <stdio.h>

namespace osquery::tables {

namespace {

static std::string getStack(CONTEXT& context_in) {
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

  CONTEXT context;
  memcpy(&context, &context_in, sizeof(CONTEXT));

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

  std::cerr << "Handling SEH" << std::endl;

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
    symbol->MaxNameLength = symbol_name_size;

    if (stack.AddrPC.Offset != 0) {
      auto res_sym = SymGetSymFromAddr64(
          process, (ULONG64)stack.AddrPC.Offset, &displacement, symbol);
      // UnDecorateSymbolName(
      //     symbol->Name, (PSTR)&name[0], name.size(), UNDNAME_COMPLETE);

      if (res_sym == FALSE) {
        std::cerr << "Failed to get symbol information" << std::endl;
        std::cerr << "Stack Frame: " << std::endl;
        std::cerr << "\tOffset: 0x" << std::hex << stack.AddrPC.Offset
                  << std::endl;
        std::cerr << "\tReturn: 0x" << std::hex << stack.AddrReturn.Offset
                  << std::endl;
        std::cerr << "\tFrame: 0x" << std::hex << stack.AddrFrame.Offset
                  << std::endl;
        std::cerr << "\tStack: 0x" << std::hex << stack.AddrStack.Offset
                  << std::endl;
        std::cerr << "\tBStore: 0x" << std::hex << stack.AddrBStore.Offset
                  << std::endl;
        std::cerr << "--------------" << std::endl;
        continue;
      }

      IMAGEHLP_LINE64 line{};
      line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
      DWORD line_displacement = 0;
      auto res_line = SymGetLineFromAddr64(
          process, (ULONG64)stack.AddrPC.Offset, &line_displacement, &line);

      if (res_line == TRUE) {
        out += line.FileName;
        out += '|';
      }

      out += symbol->Name;

      if (res_line == TRUE) {
        out += std::to_string(line.LineNumber);
        out += ':';
        out += std::to_string(line_displacement);
      }

      out += '|';
      out += (boost::format("0x%x") % (symbol->Address)).str();

      out += '\n';
    } else {
      std::cerr << "--------------" << std::endl;
      std::cerr << "PC Offset Zero" << std::endl;
      std::cerr << "Stack Frame: " << std::endl;
      std::cerr << "\tOffset: 0x" << std::hex << stack.AddrPC.Offset
                << std::endl;
      std::cerr << "\tReturn: 0x" << std::hex << stack.AddrReturn.Offset
                << std::endl;
      std::cerr << "\tFrame: 0x" << std::hex << stack.AddrFrame.Offset
                << std::endl;
      std::cerr << "\tStack: 0x" << std::hex << stack.AddrStack.Offset
                << std::endl;
      std::cerr << "\tBStore: 0x" << std::hex << stack.AddrBStore.Offset
                << std::endl;
      std::cerr << "--------------" << std::endl;
    }

  } while (result);

  return out;
}

static LONG WINAPI SEHFilterFunc(LPEXCEPTION_POINTERS exceptions) {
  printf("SEHFilter\n");

  std::cerr << "Error Code: " << exceptions->ExceptionRecord->ExceptionCode
            << std::endl;

  std::cerr << getStack(*exceptions->ContextRecord);

  return EXCEPTION_EXECUTE_HANDLER;
}

boost::optional<bool> readFirmwareBooleanVariable(
    std::string namespace_guid, const std::string& variable_name) {
  namespace_guid = "{" + namespace_guid + "}";

  std::array<std::uint8_t, 2> read_buffer;
  auto bytes_read =
      GetFirmwareEnvironmentVariableA(variable_name.c_str(),
                                      namespace_guid.c_str(),
                                      read_buffer.data(),
                                      static_cast<DWORD>(read_buffer.size()));

  if (bytes_read == 0) {
    auto error = GetLastError();
    LOG(ERROR) << "secureboot: Unable to get EFI variable " << namespace_guid
               << "::" << variable_name
               << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  if (bytes_read != 1) {
    auto error = GetLastError();
    LOG(ERROR)
        << "secureboot: The following EFI variable has an unexpected size: "
        << namespace_guid << "::" << variable_name
        << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  const auto& value = read_buffer[0];
  if (value > 1) {
    auto error = GetLastError();
    LOG(ERROR) << "secureboot: The following EFI variable is not a boolean: "
               << namespace_guid << "::" << variable_name
               << ". Value: " << static_cast<std::uint32_t>(value)
               << ". Error: " << errorDwordToString(error);

    return boost::none;
  }

  return (value == 1);
}

bool enableSystemEnvironmentNamePrivilege() {
  return false;
  TOKEN_PRIVILEGES token_privileges{};
  token_privileges.PrivilegeCount = 1;

  if (!LookupPrivilegeValueW(nullptr,
                             L"SeSystemEnvironmentPrivilege",
                             &token_privileges.Privileges[0].Luid)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to lookup the required privilege: "
               << errorDwordToString(error_code);

    return false;
  }

  token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  HANDLE process_token{INVALID_HANDLE_VALUE};
  if (OpenProcessToken(
          GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &process_token) == 0) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to open the process token: "
               << errorDwordToString(error_code);

    return false;
  }

  if (!AdjustTokenPrivileges(process_token,
                             FALSE,
                             &token_privileges,
                             sizeof(TOKEN_PRIVILEGES),
                             nullptr,
                             nullptr)) {
    auto error_code = GetLastError();
    LOG(ERROR) << "secureboot: Failed to adjust token privileges: "
               << errorDwordToString(error_code);

    return false;
  }

  auto error_code = GetLastError();
  if (error_code == ERROR_NOT_ALL_ASSIGNED) {
    LOG(ERROR) << "secureboot: Failed to adjust token privileges: "
               << errorDwordToString(error_code);
    return false;
  }

  return true;
}

} // namespace

QueryData genSecureBoot(QueryContext& context) {
  Row row;

  static const auto result = SymInitialize(GetCurrentProcess(), nullptr, TRUE);

  SetUnhandledExceptionFilter(SEHFilterFunc);

  static const auto kPrivilegeInitializationStatus{
      enableSystemEnvironmentNamePrivilege()};

  static const std::unordered_map<std::string,
                                  std::pair<std::string, std::string>>
      kRequestMap{
          {"secure_boot", std::make_pair(kEFIBootGUID, kEFISecureBootName)},
          {"setup_mode", std::make_pair(kEFIBootGUID, kEFISetupModeName)},
      };

  auto opt_firmware_kind = getFirmwareKind();
  if (!opt_firmware_kind.has_value()) {
    LOG(ERROR) << "secureboot: Failed to determine the firmware type";
    return {};
  }

  const auto& firmware_kind = opt_firmware_kind.value();
  if (firmware_kind != FirmwareKind::Uefi) {
    VLOG(1) << "secureboot: Secure boot is only supported on UEFI firmware";
    return {};
  }

  if (!kPrivilegeInitializationStatus) {
    LOG(ERROR) << "secureboot: The SE_SYSTEM_ENVIRONMENT_NAME privilege could "
                  "not be acquired. Table data may be wrong";
  }

  for (const auto& p : kRequestMap) {
    const auto& column_name = p.first;
    const auto& namespace_and_variable = p.second;

    const auto& namespace_guid = namespace_and_variable.first;
    const auto& variable_name = namespace_and_variable.second;

    auto opt_value = readFirmwareBooleanVariable(namespace_guid, variable_name);
    if (opt_value.has_value()) {
      row[column_name] = INTEGER(opt_value.value() ? 1 : 0);
    } else {
      row[column_name] = INTEGER(-1);
    }
  }

  return {std::move(row)};
}

} // namespace osquery::tables
