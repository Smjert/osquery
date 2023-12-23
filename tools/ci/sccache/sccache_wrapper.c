#include <windows.h>

#include <pathcch.h>
#include <shlwapi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_PATH_LENGTH 4096

int wmain(int argc, wchar_t* argv[]) {
  // Concatenate all the arguments separated by space
  size_t argsLen = 0;
  for (int i = 2; i < argc; i++) {
    argsLen += wcslen(argv[i]) + 1;
  }

  // Allocate memory for the arguments string
  wchar_t* args = (wchar_t*)calloc(argsLen + 1, sizeof(wchar_t));

  for (int i = 2; i < argc; i++) {
    wcscat(args, argv[i]);
    wcscat(args, L" ");
  }

  // Get the full path of the current executable
  WCHAR curExecFullName[MAX_PATH_LENGTH];
  if (!GetModuleFileNameW(NULL, curExecFullName, MAX_PATH_LENGTH)) {
    wprintf(L"Cannot get the path of the executable\n");
    free(args);
    return 1;
  }

  // Get the directory name from the full path
  HRESULT hr = PathCchRemoveFileSpec(curExecFullName, MAX_PATH_LENGTH);
  if (!SUCCEEDED(hr)) {
    fprintf(stderr, "Cannot get the directory of the executable\n");
    free(args);
    return 1;
  }

  // Construct the full path of the signal_file
  WCHAR signalFilePath[MAX_PATH_LENGTH];
  swprintf(signalFilePath,
           MAX_PATH_LENGTH,
           L"%ls\\disable_sccache",
           curExecFullName);

  STARTUPINFOW siStartupInfo;
  PROCESS_INFORMATION piProcessInfo;
  memset(&siStartupInfo, 0, sizeof(siStartupInfo));
  memset(&piProcessInfo, 0, sizeof(piProcessInfo));
  siStartupInfo.cb = sizeof(siStartupInfo);

  wchar_t* cmd = NULL;

  // Check the existence of the signal file in the same directory as the C
  // executable
  if (PathFileExistsW(signalFilePath)) {
    // If the signal file exists, run the original compiler with arguments
    int cmdLen = wcslen(argv[1]) + wcslen(args) + 2;
    cmd = (wchar_t*)calloc(cmdLen, sizeof(wchar_t));
    swprintf(cmd, cmdLen, L"%s %s", argv[1], args);
  } else {
    // If the signal file does not exist, call sccache passing all the arguments
    // to it
    int cmdLen = wcslen(L"sccache ") + wcslen(argv[1]) + wcslen(args) + 2;
    cmd = (wchar_t*)calloc(cmdLen, sizeof(wchar_t));
    swprintf(cmd, cmdLen, L"sccache %s %s", argv[1], args);
  }

  // CreateProcessW
  if (!CreateProcessW(NULL,
                      cmd,
                      NULL,
                      NULL,
                      FALSE,
                      0,
                      NULL,
                      NULL,
                      &siStartupInfo,
                      &piProcessInfo)) {
    fprintf(stderr, "Create process failed(%d)", GetLastError());
    free(cmd);
    free(args);
    return 1;
  }

  // Wait for the child process to exit
  WaitForSingleObject(piProcessInfo.hProcess, INFINITE);

  // Close handles to the child process and its primary thread
  CloseHandle(piProcessInfo.hProcess);
  CloseHandle(piProcessInfo.hThread);

  free(cmd);
  free(args);

  return 0;
}
