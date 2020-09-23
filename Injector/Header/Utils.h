#pragma once
#include <Windows.h>

#ifdef __cplusplus
EXTERN_C_START
#endif

BOOL is32Bit(HANDLE hProcess);
BOOL setPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL isAppRunningAsAdminMode(VOID);
BOOL setPrivilegeIfModeAdmin(VOID);

#ifdef __cplusplus
EXTERN_C_END
#endif

