#include <Windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, const DWORD ulReasonForCall,
                      LPVOID lpReserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    UNREFERENCED_PARAMETER(ulReasonForCall);
    return TRUE;
}
