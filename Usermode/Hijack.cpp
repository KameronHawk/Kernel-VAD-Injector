#include "Hijack.h"


typedef BOOL (__fastcall* NtAlertThreadByThreadID)(uintptr_t ThreadID);

bool MemoryCmp(const BYTE* Data, const BYTE* Mask, const char* szMask) {
	for (; *szMask; ++szMask, ++Data, ++Mask) {
		if (*szMask == '\?' && *Data != *Mask) {
			return false;
		}
	}
	return (*szMask == NULL);
}



uintptr_t FindSignaturee(uintptr_t Start, UINT32 Size, const char* Sig, const char* Mask, HANDLE ProcessID) {
	BYTE* Data = new BYTE[Size];
	SIZE_T BytesRead;
	ReadMemory(ProcessID, (PVOID)Start, Size, Data);

	for (uint32_t i = 0; i < Size; i++) {
		if (MemoryCmp((const BYTE*)(Data + i), (const BYTE*)Sig, Mask)) {
			return Start + i;
		}
	}
	delete[] Data;
	return NULL;

}


BYTE RemoteCallDllMain[] = {//0x48 first byte
	0x48, 0x83, 0xEC, 0x38,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x39, 0xFF, 0x90, 0x39, 0xC0,
		0x90,
		0x48, 0x89, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x44, 0x24,
		0x20, 0x83, 0x38, 0x00, 0x75, 0x39,
		0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20,
		0x48, 0x8B,
		0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x81, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0x48,
		0x39, 0xC0, 0x90, 0xCC
}; DWORD ShellDataOffset = 0x6;


BYTE Shellcode[] = { 0x48, 0xB8, 
0x00, 0xBE, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 
0xFF, 0xE0 };



typedef struct _MAIN_STRUCT {
	INT Status;
	uintptr_t FnDllMain;
	HINSTANCE DllBase;
} MAIN_STRUCT, * PMAIN_STRUCT;


BOOL Hijack::CallDllMain(DWORD ProcessID, DWORD ThreadID, PVOID DllBase, DWORD AddressOfEntryPoint) {
	PVOID AllocShellCode = NULL;
	AllocMemory((HANDLE)ProcessID, &AllocShellCode, 0x1000, PAGE_EXECUTE_READWRITE);

	if (!AllocShellCode) {
		printf(skCrypt("[-] Failed to Allocate ShellCode...\n"));
		return FALSE;
	}

	DWORD ShellSize = sizeof(RemoteCallDllMain) + sizeof(MAIN_STRUCT);
	PVOID AllocLocal = VirtualAlloc(NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!AllocLocal) {
		printf(skCrypt("[-] Failed to allocate local mem\n"));
		return FALSE;
	}
	memcpy(AllocLocal, &RemoteCallDllMain, sizeof(RemoteCallDllMain));

	ULONGLONG ShellData = (ULONGLONG)AllocShellCode + sizeof(RemoteCallDllMain);
	memcpy((void*)((std::uintptr_t)AllocLocal + 0x6), &ShellData, sizeof(std::uintptr_t));

	auto remote = (PMAIN_STRUCT)((std::uintptr_t)AllocLocal + sizeof(RemoteCallDllMain));
	remote->DllBase = (HINSTANCE)DllBase;
	remote->FnDllMain = ((std::uintptr_t)DllBase + AddressOfEntryPoint);
	WriteMemory((HANDLE)ProcessID, (DWORD64)AllocShellCode, ShellSize, AllocLocal);

	PVOID ModBase{0};
	PVOID ModBaseSize{ 0 };
	GetBase(&ModBase, &ModBaseSize, "DiscordHook64.dll", (HANDLE)ProcessID);

	if (!ModBase) {
		printf(skCrypt("[-] Failed to obtain DLL base for hook!\n\n"));
		return FALSE;
	}


	uintptr_t FuncToHook = ((uintptr_t)ModBase + 0xE8090);//E8090 SwapChain::Present
	printf(skCrypt("[*] Shellcode Allocation -> 0x%X\n"), AllocShellCode);




	PVOID pOldFuncPtr;
	SwapPointer((HANDLE)ProcessID, (PVOID)FuncToHook, (PVOID)AllocShellCode, &pOldFuncPtr);

	

	HWND hWnd = 0;
	while (remote->Status != 0x81)
	{
		
		printf("[*] Status -> %d\n", remote->Status);

		hWnd = FindWindowA(skCrypt("gfx_test"), NULL);
		
		if (hWnd == NULL) {
			printf(skCrypt("\n[-]Game Closed.. exiting\n"));
			return FALSE;
		}
		Sleep(10);
		ReadMemory((HANDLE)ProcessID, (PVOID)ShellData, sizeof(MAIN_STRUCT), (PVOID)remote);
	}

	printf(skCrypt("[*] Executed DLL!\n"));

	
	PVOID pNewOldPtr{ 0 };
	SwapPointer((HANDLE)ProcessID, (PVOID)FuncToHook, (PVOID)pOldFuncPtr, &pNewOldPtr);
	
	
	printf(skCrypt("[*] Hiding Traces...\n"));
	
	BYTE ZeroData[0x1000] = {0};
	WriteMemory((HANDLE)ProcessID, (DWORD64)AllocShellCode, 0x1000, &ZeroData);
	FreeMemory((HANDLE)ProcessID, (PVOID)AllocShellCode);
	LI_FN(VirtualFree).get()((PVOID)AllocLocal, 0, MEM_RELEASE);

    return true;
}
