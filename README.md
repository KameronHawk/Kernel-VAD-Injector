# Driver DLL Injector
Driver DLL Injector
Description

Driver DLL Injector is a powerful tool that allows users to load drivers of their choice using their preferred mapper. By leveraging the capabilities of an unsigned driver loader, such as KDmapper, this injector empowers users to expand their system's functionalities and explore new possibilities.

## Driver Portion:

  The driver hooks a patch guard safe function known as xKdEnumerateDebuggingDevices for communication with our usermode process. This method is highly detected on popular anti-cheats, so we go a step further and trap a usermode thread in kernel to communicate restoring the original functions address therefore bypassing function integrity checks.

  The driver does the following for hiding traces left behind:

   - VAD Manipulation: The driver strategically allocates memory behind the "thread stack" by leveraging undocumented Virtual Address Descriptor (VAD) functions like MiInsertChange and MiAllocVad, which are not widely known. Once the VAD is allocated and DLL is sucessfully loaded the driver will remove the VAD from the VAD tree. 

  - PTE Manipulation: To bypass checks from NtQueryVirtualMemory, the driver manipulates Page Table Entries (PTEs) to make the pages allocated by VAD executable. By modifying the PTEs, the driver ensures that the VAD does not update with the executable (X) bit enabled, circumventing potential restrictions.
  - Clearing PiDDBCacheTable, MmUnloadedDrivers (Hash Bucket List).
  - Depending on what manual mapper you use for the driver, you will have to also take into account big pools.

## Usermode Portion:

 The usermode process utilizes Discord's overlay to call our DLL main's function.

  The usermode process does the following:
  - "Links" with the hooked kernel function, supplying all of our address's and message codes.
  - Scans the process for Discord overlay, if found setup shellcode, and allocate VAD.
  - Setup shellcode for calling DLL main, and then 
  - Once the DLL is injected the usermode process will send a message to the driver saying "We're done!" and the driver will clean up all of the traces that are left behind.

To use the Driver DLL Injector, follow these steps:

    1. Choose and install a compatible mapper, such as KDmapper.
    2. Compile or build the Driver DLL Injector project.
    3. Load the driver using the selected mapper
    4. Launch test application (with discord overlay enabled)
    5. Launch usermode application and wait for Hello World message box.


## Issues Encountered
 When making this project, there were several blocks along the way. Some of the following were:

 - DLL crashing because the DLL properties were setup wrongly. Setting ```/sdl-```, ```/GS-```, and runtime library to ```/MT``` fixed my issues with crashing.
 - Mapping the driver using a mapper would cause a ```KMODE_EXCEPTION``` BSOD, fixing this by setting the driver property ```/GS-```.
 - Discords overlay takes time to initalize, if you try to inject before the overlay is initalized you will crash because of NULL pointers.
