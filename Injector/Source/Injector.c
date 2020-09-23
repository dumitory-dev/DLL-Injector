// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java:
// http://www.viva64.com

// Based on https://github.com/iamclint/libinj

#include "Injector.h"

#include <Psapi.h>
#include <TlHelp32.h>
#include <string.h>
#include <tchar.h>

static BOOL privateInject(const char *dllPath,
                          LPTHREAD_START_ROUTINE pLoadLibrary, HANDLE hProcess)
{
    HANDLE hThread = NULL;
    DWORD dwExitCode = INFINITE;
    DWORD dWord = 0;
    CONST SIZE_T dllPathLen = (SIZE_T)strlen(dllPath) + sizeof(char);

    LPVOID hVirtualAlloc = VirtualAllocEx(hProcess, NULL, dllPathLen,
                                          MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!hVirtualAlloc)
    {
        goto clean;
    }

    if (!WriteProcessMemory(hProcess, hVirtualAlloc, dllPath, dllPathLen, 0))
    {
        goto clean;
    }

    hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, hVirtualAlloc,
                                 0, &dWord);
    if (!hThread)
    {
        goto clean;
    }

    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &dwExitCode);

clean:
    if (hVirtualAlloc)
    {
        VirtualFreeEx(hProcess, hVirtualAlloc, 0, MEM_RELEASE);
    }
    if (hThread)
    {
        CloseHandle(hThread);
    }
    if (dwExitCode == 0u)
    {
        return FALSE;
    }

    return GetLastError() == 0u;
}

LPTHREAD_START_ROUTINE getCorrectLoadLibrary(HANDLE hProcess)
{
    if (is32Bit(hProcess))
    {
        return (LPTHREAD_START_ROUTINE)getFunctionAddress32(
            "kernelbase.dll", "loadlibrarya", hProcess);
    }

    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (!hKernel32)
    {
        return 0;
    }

    return (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
}

BOOL injectX86X64(const char *dllPath, const DWORD pid)
{
    if (dllPath == NULL)
    {
        return FALSE;
    }

    if (!setPrivilegeIfModeAdmin() && GetLastError() != (unsigned)ERROR_SUCCESS)
    {
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        return FALSE;
    }

    const LPTHREAD_START_ROUTINE correctLoadLibrary =
        getCorrectLoadLibrary(hProcess);

    if (!correctLoadLibrary)
    {
        return FALSE;
    }

    const BOOL res = privateInject(dllPath, correctLoadLibrary, hProcess);
    CloseHandle(hProcess);

    return res;
}

BOOL injectX86(const char *dllPath, const DWORD pid)
{
    if (!dllPath)
    {
        return FALSE;
    }

    if (!setPrivilegeIfModeAdmin() && GetLastError() != (unsigned)ERROR_SUCCESS)
    {
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));

    if (!hKernel32)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    const LPTHREAD_START_ROUTINE correctLoadLibrary =
        (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");

    const BOOL res = privateInject(dllPath, correctLoadLibrary, hProcess);
    CloseHandle(hProcess);
    return res;
}

BOOL inject(const char *dllPath, DWORD pid)
{
    return is32Bit(GetCurrentProcess()) ? injectX86(dllPath, pid)
                                        : injectX86X64(dllPath, pid);
}

SIZE_T getFunctionAddress32(const char *moduleName, const char *functionName,
                            HANDLE hProcess)
{
    // see https://afly.co/x663

    const SIZE_T modBase = getModuleBase(hProcess, moduleName);
    if (modBase == 0u)
    {
        return 0;
    }

    IMAGE_DOS_HEADER dosHeaders;
    IMAGE_NT_HEADERS32 ntHeaders;
    IMAGE_EXPORT_DIRECTORY exportDirectory;

    ReadProcessMemory(hProcess, (LPVOID)(modBase), (LPVOID)(&dosHeaders),
                      sizeof(IMAGE_DOS_HEADER), 0);

    if (dosHeaders.e_magic != (unsigned)IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    if (!ReadProcessMemory(
            hProcess, (LPVOID)((size_t)modBase + (DWORD)dosHeaders.e_lfanew),
            (LPVOID)&ntHeaders, sizeof(IMAGE_NT_HEADERS32), 0))
    {
        return 0;
    }

    if (!ReadProcessMemory(
            hProcess,
            (LPVOID)((SIZE_T)ntHeaders.OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                         .VirtualAddress +
                     modBase),
            (LPVOID)(&exportDirectory), sizeof(IMAGE_EXPORT_DIRECTORY), 0))
    {
        return 0;
    }

    for (DWORD i = 0; i < exportDirectory.NumberOfFunctions; i++)
    {
        DWORD currentFunctionNamePtr;
        WORD currentFunctionNameOrdinalsPtr;
        DWORD currentFunctionVirtualAddress;

        char currentFunctionName[61] = {'\0'};

        if (!ReadProcessMemory(hProcess,
                               (LPVOID)((SIZE_T)modBase +
                                        exportDirectory.AddressOfNames +
                                        (i * sizeof(DWORD))),
                               &currentFunctionNamePtr, sizeof(DWORD),
                               NULL)) // get the virtual address to the name
        {
            return 0;
        }

        if (!ReadProcessMemory(
                hProcess, (LPVOID)(modBase + (SIZE_T)currentFunctionNamePtr),
                &currentFunctionName, sizeof(currentFunctionName) - 1,
                NULL)) // read the name
        {
            return 0;
        }

        if (!ReadProcessMemory(
                hProcess,
                (LPVOID)(modBase + exportDirectory.AddressOfNameOrdinals +
                         (i * sizeof(WORD))),
                &currentFunctionNameOrdinalsPtr, sizeof(WORD), 0))
        {
            return 0;
        }

        if (!ReadProcessMemory(
                hProcess,
                (LPVOID)(modBase + exportDirectory.AddressOfFunctions +
                         (currentFunctionNameOrdinalsPtr * sizeof(DWORD))),
                &currentFunctionVirtualAddress, sizeof(DWORD), NULL))
        {
            return 0;
        }

        if (_stricmp(currentFunctionName, functionName) == 0)
        {
            return modBase + currentFunctionVirtualAddress;
        }
    }

    return 0;
}

SIZE_T getModuleBase(HANDLE hProcess, const char *moduleName)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded,
                         LIST_MODULES_ALL);

    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        char tmpModName[256];
        memset(tmpModName, 0, sizeof(tmpModName));
        if (GetModuleBaseNameA(hProcess, hMods[i], tmpModName,
                               sizeof(tmpModName)))
        {
            if (_stricmp(moduleName, tmpModName) == 0)
            {
                MODULEINFO moduleInfo;
                GetModuleInformation(hProcess, hMods[i], &moduleInfo, cbNeeded);
                return (SIZE_T)(moduleInfo.lpBaseOfDll);
            }
        }
    }
    return 0;
}

SIZE_T getBaseAddress(const DWORD pid)
{
    MODULEENTRY32 me32;
    HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModule == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    if (!Module32First(hModule, &me32))
    {
        CloseHandle(hModule);
        return 0;
    }

    const SIZE_T rVal = (SIZE_T)me32.modBaseAddr;
    CloseHandle(hModule);
    return rVal;
}

DWORD getError(VOID)
{
    return GetLastError();
}
