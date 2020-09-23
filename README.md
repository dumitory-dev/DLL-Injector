# Simple DLL Injector

### Appointment
This simple injector is for injecting DLL into processes.

###  Functionality
1. Checking administrator rights. (If the process has administrator rights, then the rights are set. It is also possible to use an injector without administrator rights (then DLL injection will be possible only in the processes of the current session)).
2. X64 injector can inject DLL into X64 and X86 processes.
3. X86 injector can inject DLL into X86 processes.

###  Implementation details
The injector uses the offset of the virtual address to find the Wow64 address of the LoadLibrary function.<br>
-   Approximate order of actions:  
    -   64 bit Injector retrieves address of kernel32.dll loaded by 32 bit target using EnumProcessModulesEx().
    -   Get filename of that kernel32.dll, parse the PE header and get the RVA of LoadLibraryA.
    -   At this point, we know where kernel32.dll is loaded in the 32 bit target and the address of the function from this DLL.
    -   64 bit Injector starts remote thread in 32 bit target with ImageBase + Function RVA.
    
Supported OS: Win7 - Win10 x86 x64

# Using

``` c++
#include <Windows.h>
#include <memory>
#include <iostream>

using inject_func = BOOL(__cdecl*)(const char* dllPath, DWORD pid);
using error_func = DWORD(__cdecl*)();

int main() {
	
	try
	{
		std::unique_ptr<HINSTANCE__, decltype(&::FreeLibrary)> const p_library
		{
			::LoadLibrary(TEXT("Injector.dll")),
			::FreeLibrary
		};

		if (!p_library)
		{
			return EXIT_FAILURE;
		}

		auto const inject = reinterpret_cast<inject_func>(::GetProcAddress(p_library.get(), "inject"));
		auto const get_error = reinterpret_cast<error_func>(::GetProcAddress(p_library.get(), "getError"));

		if(!inject || !get_error)
		{
			return EXIT_FAILURE;
		}

		if (!inject("path_to_dll", 0))
		{
			std::cerr << get_error() << std::endl;
			return EXIT_FAILURE;
		}
	}
	catch (std::exception const& error)
	{
		std::cerr << error.what() << std::endl;
	}
	
}


```


# License
Injector is licensed under the MIT License. Dependencies are under their respective licenses.
