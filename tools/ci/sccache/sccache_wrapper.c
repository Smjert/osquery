#include <pathcch.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_PATH_LENGTH 4096

int main(int argc, char* argv[]) {
  // Concatenate all the arguments separated by space
  int argsLen = 0;
  for (int i = 2; i < argc; i++) {
    argsLen += strlen(argv[i]) + 1; // add the length of argument + 1 for space
  }

  // Allocate memory for the arguments string
  char* args = (char*)malloc((argsLen + 1) * sizeof(char));
  args[0] = '\0'; // Init the string

  for (int i = 2; i < argc; i++) {
    strcat(args, argv[i]);
    strcat(args, " ");
  }

  // Get the full path of the current executable
  WCHAR curExecFullName[MAX_PATH_LENGTH];
  if (!GetModuleFileNameW(NULL, curExecFullName, MAX_PATH_LENGTH)) {
    wprintf(L"Cannot get the path of the executable\n");
    return 1;
  }

  // Get the directory name from the full path
  HRESULT hr = PathCchRemoveFileSpec(curExecFullName, MAX_PATH_LENGTH);
  if (!SUCCEEDED(hr)) {
    wprintf(L"Cannot get the directory of the executable\n");
    return 1;
  }

  // Construct the full path of the signal_file
  WCHAR signalFilePath[MAX_PATH_LENGTH];
  swprintf(signalFilePath,
           MAX_PATH_LENGTH,
           L"%ls\\disable_sccache",
           curExecFullName);

  FILE* disable_sccache = NULL;

  // Check the existence of the signal file in the same directory as the C
  // executable
  if (PathFileExistsW(signalFilePath)) {
    // If the signal file exists, run the original compiler with arguments
    int cmdLen = strlen(argv[1]) + 1 + argsLen + 1;
    char* cmd = (char*)malloc(cmdLen + 1);
    snprintf(cmd, cmdLen + 1, "%s %s", argv[1], args);
    system(cmd);
    free(cmd);
  } else {
    // If the signal file does not exist, call sccache passing all the arguments
    // to it
    int cmdLen = sizeof("sccache ") - 1 + strlen(argv[1]) + argsLen;
    char* cmd = (char*)malloc(cmdLen + 1);
    snprintf(cmd, cmdLen + 1, "sccache %s %s", argv[1], args);
    system(cmd);
    free(cmd);
  }

  free(args);
  return 0;
}
