#pragma once
#include "ntapi.h"
#include "Util.h"
#include "Logs.h"
#include "SkCrypt.h"
#include "ia32.h"
#include <intrin.h>
#include "Comm.h"

typedef struct _PAGE_INFO_ {
	PML4E_64* PML4E = { 0 };

	PDPTE_64* PDPTE = { 0 };

	PDE_64* PDE = { 0 };

	PTE_64* PTE = { 0 };

	UINT64 PAOffset = { 0 };
}PAGE_INFO, * pPAGE_INFO;

namespace Memory {

	NTSTATUS ReadVirtualMemory(HANDLE ProcessID, PVOID AddressToRead, PVOID AddressToStoreInfo, SIZE_T Size);

	NTSTATUS WriteVirtualMemory(HANDLE ProcessID, PVOID AddressToWrite, PVOID ValueToWrite, SIZE_T Size);

	NTSTATUS AllocateMemory(HANDLE ProcessID, PVOID pOut, ULONG_PTR Protection, SIZE_T Size);


	NTSTATUS ReadPhysicalAddress(UINT64 TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead);

	NTSTATUS ProtectVirtualMemory(HANDLE ProcessID, PVOID Address, SIZE_T SizeOfMem, PVOID oldProtOut, ULONG NewProt, bool UseOldSize);

	NTSTATUS InitializeFuncs();


	NTSTATUS QueryVirtualMemory(HANDLE ProcessID, PVOID AddressToQuery, MEMORY_INFORMATION_CLASS MemClass, PVOID AddressToStore, SIZE_T Size);

	namespace VAD {
		NTSTATUS AllocateVAD(HANDLE ProcessID, PVOID Address, SIZE_T Size);

		NTSTATUS FindVAD(PEPROCESS Process, ULONG_PTR Address, PMMVAD_SHORT* pResult);

		TABLE_SEARCH_RESULT
			MiFindNodeOrParent(
				IN PMM_AVL_TABLE Table,
				IN ULONG_PTR StartingVpn,
				OUT PMMADDRESS_NODE* NodeOrParent);
	};


	CR3 GetProcessCR3(PEPROCESS Process);

	BOOLEAN SafeCopy(PVOID Destination, PVOID Source, SIZE_T Size);

	NTSTATUS GetPte(HANDLE ProcessID, PVOID Address, PTE_64** pOut);
	
	NTSTATUS SetPte(PTE_64* PTE);

	PVOID ResolveRelativeAddress(PVOID Instruction, ULONGLONG OffsetOffset, ULONG InstructionSize);

	uintptr_t find_pattern(uintptr_t base, const char* pattern, const char* mask);

	uintptr_t find_pattern2(uintptr_t base, size_t range, const char* pattern, const char* mask);


	PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class);

	uintptr_t GetKernelModule(const char* name);

	uintptr_t find_pattern3(uintptr_t module_base, const char* pattern);

	NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);

	NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);

	BOOLEAN WriteToReadOnly(PVOID Dst, PVOID Buff, SIZE_T Size);



};


