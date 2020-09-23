#pragma once
#include <Windows.h>

#ifdef __cplusplus
EXTERN_C_START
#endif

LPTHREAD_START_ROUTINE getCorrectLoadLibrary(HANDLE hProcess);

BOOL injectX86X64(const char *dllPath, DWORD pid);
BOOL injectX86(const char *dllPath, DWORD pid);
BOOL inject(const char *dllPath, DWORD pid);

SIZE_T getFunctionAddress32(const char *moduleName, const char *functionName,
                           HANDLE hProcess);
SIZE_T getBaseAddress(DWORD pid);
SIZE_T getModuleBase(HANDLE hProcess, const char *moduleName);
DWORD getError(VOID);

#ifdef __cplusplus
EXTERN_C_END
#endif
