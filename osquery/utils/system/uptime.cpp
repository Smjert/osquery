/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/utils/system/uptime.h>

#if defined(__APPLE__)
#include <errno.h>
#include <sys/sysctl.h>
#include <time.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#elif defined(WIN32)
#include <Windows.h>
#include <winperf.h>
#include <cstdint>
#include <iostream>
#endif

namespace osquery {

long getUptime() {
#if defined(DARWIN)
  struct timeval boot_time;
  size_t len = sizeof(boot_time);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};

  if (sysctl(mib, 2, &boot_time, &len, nullptr, 0) < 0) {
    return -1;
  }

  time_t seconds_since_boot = boot_time.tv_sec;
  time_t current_seconds = time(nullptr);

  return long(difftime(current_seconds, seconds_since_boot));
#elif defined(__linux__)
  struct sysinfo sys_info;

  if (sysinfo(&sys_info) != 0) {
    return -1;
  }

  return sys_info.uptime;
#elif defined(WIN32)

  PERF_DATA_BLOCK *dataBlock = NULL;
  PERF_OBJECT_TYPE *objType;
  PERF_COUNTER_DEFINITION *counterDef;
  PERF_COUNTER_DEFINITION *counterDefUptime = NULL;
  DWORD dataSize = 4096;
  DWORD getSize;
  LONG lError = ERROR_MORE_DATA;
  uint64_t upsec;
  unsigned int i;
  BYTE *counterData;

  while (lError == ERROR_MORE_DATA) {
    std::cout << "Enter Loop!" << std::endl;
    if (dataBlock) {
      delete[] dataBlock;
    }
    dataBlock = new PERF_DATA_BLOCK[dataSize];
    if (!dataBlock) {
      std::cerr << "Out of memory!" << std::endl;
      return -1;
    }
    getSize = dataSize;

    lError = RegQueryValueExW(HKEY_PERFORMANCE_DATA, L"2", NULL, NULL,
                             (BYTE*)dataBlock, &getSize);
    if (lError != ERROR_SUCCESS && getSize > 0) {
      if (wcsncmp(dataBlock->Signature, L"PERF", 4) == 0) {
        break;
      }
    } else if (lError != ERROR_SUCCESS && lError != ERROR_MORE_DATA) {
      std::cerr << GetLastError() << std::endl;
      goto done;
    }

    dataSize += 1024;
    std::cout << "Loop!" << std::endl;
  }

  RegCloseKey(HKEY_PERFORMANCE_DATA);

  objType = (PERF_OBJECT_TYPE*)((BYTE*)dataBlock + dataBlock->HeaderLength);
  counterDef = (PERF_COUNTER_DEFINITION*)((BYTE*)objType + objType->HeaderLength);

  for (i = 0; i < objType->NumCounters; ++i) {
    if (counterDef->CounterNameTitleIndex == 674) {
      counterDefUptime = counterDef;
      break;
    }
    counterDef = (PERF_COUNTER_DEFINITION*)((BYTE*)counterDef + counterDef->ByteLength);
  }

  counterData = (BYTE*)objType + objType->DefinitionLength;
  counterData += counterDefUptime->CounterOffset;

  upsec = *((uint64_t*)counterData);
  auto uptime = ((objType->PerfTime.QuadPart - upsec) / objType->PerfFreq.QuadPart);

done:
  if (dataBlock) {
    delete[] dataBlock;
  }

  return uptime;
 // return static_cast<long>(GetTickCount64() / 1000);
#endif

  return -1;
}

} // namespace osquery
