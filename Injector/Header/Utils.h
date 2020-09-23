#pragma once
#include <Windows.h>

#ifdef CPPDLL_EXPORTS
#define DLLIMPORT_EXPORT __declspec(dllexport)
#else
#define DLLIMPORT_EXPORT __declspec(dllimport)
#endif

#ifdef __cplusplus
EXTERN_C_START
#endif

DLLIMPORT_EXPORT BOOL is32Bit(HANDLE hProcess);
DLLIMPORT_EXPORT BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
DLLIMPORT_EXPORT BOOL isAppRunningAsAdminMode(VOID);
DLLIMPORT_EXPORT BOOL setPrivilegeIfModeAdmin(VOID);

#ifdef __cplusplus
EXTERN_C_END
#endif

