#pragma once
#include <Windows.h>
#include "Utils.h"


#ifdef __cplusplus
EXTERN_C_START
#endif

LPTHREAD_START_ROUTINE getCorrectLoadLibrary(HANDLE hProcess);

DLLIMPORT_EXPORT BOOL injectX86X64(const char *dllPath, DWORD pid);
DLLIMPORT_EXPORT BOOL injectX86(const char *dllPath, DWORD pid);
DLLIMPORT_EXPORT BOOL inject(const char *dllPath, DWORD pid);

DLLIMPORT_EXPORT SIZE_T getFunctionAddress32(const char *moduleName, const char *functionName,
                           HANDLE hProcess);
DLLIMPORT_EXPORT SIZE_T getBaseAddress(DWORD pid);
DLLIMPORT_EXPORT SIZE_T getModuleBase(HANDLE hProcess, const char *moduleName);

DLLIMPORT_EXPORT DWORD getError(VOID);

#ifdef __cplusplus
EXTERN_C_END
#endif
