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

# License
Injector is licensed under the MIT License. Dependencies are under their respective licenses.
