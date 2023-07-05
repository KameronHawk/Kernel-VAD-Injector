#include <Windows.h>
#include "LazyImp.h"
#include "SharedMemory.h"
#include "skCrypter.h"
#include "Memory.h"

#pragma warning(disable : 4996)
#define RTSS_FUNC_TO_HOOK		"\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x48\x89\x7C\x24\x00\x41\x54\x48\x83\xEC\x20\xF0\x0F\xBA\x2D\x00\x00\x00\x00\x00"
#define RTSS_FUNC_TO_HOOK_MASK	"xxxx?xxxx?xxxx?xxxx?xxxxxxxxxx?????"


#define WIN32_FUNC_PATTERN		"\x4C\x8B\xD1\xB8\x24\x10"
#define WIN32_FUNC_MASK			"xxxxxx"






namespace Hijack {




	BOOL CallDllMain(DWORD ProcessID, DWORD ThreadID, PVOID DllBase, DWORD AddressOfEntryPoint);



}

