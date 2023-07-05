#pragma once
#include "Memory.h"
#include <ntimage.h>
#include <minwindef.h>
#include "CRT.h"
#include "ia32.h"

#define MI_ALLOCATE_VAD_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9"
#define MI_ALLOCATE_VAD_MASK "xxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define MI_INSERT_VAD_CHANGES_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x18"
#define MI_INSERT_VAD_CHANGES_MASK "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


#define MI_INSERT_VAD_PATTERN "\x48\x89\x5C\x24\x08\x48\x89\x6C\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x1C"
#define MI_INSERT_VAD_MASK "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"


#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

typedef struct _NTOS_BASE_INFO {
	PVOID BaseAddress = { 0 };
	SIZE_T SizeOfModule = { 0 };
}NtosBaseInfo, * pNtosBaseInfo;


struct PAGE_INFORMATION
{
	PML4E_64* PML4E;
	PDPTE_64* PDPTE;
	PDE_64* PDE;
	PTE_64* PTE;
};




typedef struct _MDL_INFORMATION
{
	MDL* mdl;
	uintptr_t va;
}MDL_INFORMATION, * PMDL_INFORMATION;






namespace Util {
	namespace Process {

		HANDLE GetProcessIDByName(IN UNICODE_STRING ProcessName);

		PVOID GetLastThreadStack(HANDLE ProcessID, PVOID pOut, PVOID pThreadID);

		NTSTATUS GetThreadTEBs(HANDLE ProcessID, PVOID* TEBs, PVOID* ThreadID);

		PVOID /*PT_ENTRY_64**/ GetPTE(PVOID Address, HANDLE ProcessID);

		NTSTATUS SetPte(HANDLE ProcessID, PVOID Address);

		NTSTATUS RemoveVAD(HANDLE ProcessID, PVOID Address);

		NTSTATUS FreeMemory(HANDLE ProcessID, PVOID AddressToFree);

		NTSTATUS SwapPointer(HANDLE ProcessID, PVOID Destination, PVOID Source, PVOID pOutOld);

		PVOID GetDllBase(HANDLE ProcessID, PCWSTR DllName, bool is32Bit, PVOID OutSize);

		PVOID GetModuleExport(PVOID pBase, PCHAR FunctionName);

		PPEB64 GetProcessPeb(PEPROCESS TargetProcess);

		uintptr_t FindPattern(uintptr_t ModuleBase, const char* Pattern);

		uintptr_t BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

		BOOL IsProcessOpen(HANDLE ProcessID);


	};

	PVOID GetDriverBase(IN const char* DriverName, OUT pNtosBaseInfo pModBaseInfo);

	NTSTATUS SearchPattern(IN PCUCHAR Pattern, IN UCHAR Wildcard, IN ULONG_PTR Len, IN const VOID* Base, IN ULONG_PTR Size, OUT PVOID* ppFound, int index = 0);

	BOOL CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask);

	PVOID FindPattern(PCHAR Base, DWORD Length, PCHAR Pattern, PCHAR Mask);

	PVOID FindPatternImage(PCHAR Base, PCHAR Pattern, PCHAR Mask);

	BOOL SpoofPTE(PVOID Address, HANDLE ProcessID);


	uintptr_t FindPatternInsideDll(HANDLE ProcessID, uintptr_t BaseOfModule, const char* Signature, const char* mask);

	NTSTATUS GetProcessBase(HANDLE ProcessID, PVOID pOut, PVOID pSizeOut);

	PVOID GetExportedFunction(CONST ULONGLONG Base, CONST CHAR* Name);

	UCHAR RandomNum();

	PVOID PrintDriverNames();

	VOID Sleep(INT ms);

	template <typename T>
	BOOLEAN WriteSharedMemory(PVOID Address, T Buffer, SIZE_T Size = sizeof(T));

	template<typename T>
	BOOLEAN WriteSharedMemory(PVOID Address, T Buffer, SIZE_T Size) {

		SIZE_T Bytes{ 0 };

		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)&Buffer, gProcess, Address, Size, KernelMode, &Bytes))) {
			return TRUE;
		}
		return FALSE;
	}


	BOOLEAN ReadSharedMemory(PVOID Address, PVOID Buffer, SIZE_T Size, PEPROCESS Process);

	MDL_INFORMATION AllocateMdlMem(SIZE_T Size);


	PVOID AllocateKernelMemory(SIZE_T Size, uintptr_t* MDL);

	void FreeMdlMemory(MDL_INFORMATION& Memory);

	BOOL ExposeKernelMemory(HANDLE ProcessID, uintptr_t KernelAddress, SIZE_T Size);

	PAGE_INFORMATION GetPageInfo(PVOID Va, CR3 cr3);
};