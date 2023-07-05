#include "hide.h"
#include "Util.h"
#include "Memory.h"

#define MM_UNLOADED_DRIVERS_SIZE 50

typedef struct _PIDDBCACHE_ENTRY {
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PIDDBCACHE_ENTRY, * PPIDDBCACHE_ENTRY;

typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

PERESOURCE
GetPsLoaded() {
	auto n = skCrypt("ntoskrnl.exe");
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);
	n.clear();
	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(Util::GetExportedFunction((ULONGLONG)BaseInfo.BaseAddress, "MmGetSystemRoutineAddress"));

	ERESOURCE PsLoadedModuleResource;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(cMmGetSystemRoutineAddress(&routineName));

	return cPsLoadedModuleResource;
}

PMM_UNLOADED_DRIVER
GetMmuAddress() {
	auto n = skCrypt("ntoskrnl.exe");
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);

	auto MmuPattern = skCrypt(MMU_PATTERN);
	auto MmuMask = skCrypt(MMU_MASK);
	PVOID MmUnloadedDriversInstr = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, MmuPattern, MmuMask);
	MmuPattern.clear();
	MmuMask.clear();

	if (MmUnloadedDriversInstr == NULL)
		return { };

	return *(PMM_UNLOADED_DRIVER*)Memory::ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	auto n = skCrypt("ntoskrnl.exe");
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);

	auto MmlPattern = skCrypt(MML_PATTERN);
	auto MmlMask = skCrypt(MML_MASK);
	PVOID mmlastunloadeddriverinst = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, MmlPattern, MmlMask);
	MmlPattern.clear();
	MmlMask.clear();

	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)Memory::ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
	PMM_UNLOADED_DRIVER Entry
) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;

	return FALSE;
}

BOOL
IsMmuFilled() {
	for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
		if (IsUnloadEmpty(Entry))
			return FALSE;
	}
	return TRUE;
}

BOOL
CleanMmu(
	UNICODE_STRING DriverName
) {
	auto ps_loaded = GetPsLoaded();

	ExAcquireResourceExclusiveLite(ps_loaded, TRUE);

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmuFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
		if (IsUnloadEmpty(Entry)) {
			continue;
		}
		BOOL empty = IsUnloadEmpty(Entry);
		if (Modified) {
			PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
		}
		else if (RtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 'TDmM');

			*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
			Modified = TRUE;
		}
	}

	if (Modified) {
		ULONG64 PreviousTime = 0;

		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
			if (IsUnloadEmpty(Entry)) {
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
				Entry->UnloadTime = PreviousTime - Util::RandomNum();
			}

			PreviousTime = Entry->UnloadTime;
		}

		CleanMmu(DriverName);
	}

	ExReleaseResourceLite(ps_loaded);

	return Modified;
}

PERESOURCE
GetPiDDBLock() {
	auto n = skCrypt("ntoskrnl.exe");
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);
	auto PiDDBLockPattern = skCrypt(PIDDB_LOCK_PATTERN);
	auto PiDDBLockMask = skCrypt(PIDDB_LOCK_MASK);
	PERESOURCE PiDDBLock = (PERESOURCE)Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, PiDDBLockPattern.decrypt(), PiDDBLockMask.decrypt());
	PiDDBLockPattern.clear();
	PiDDBLockMask.clear();
	PiDDBLock = (PERESOURCE)Memory::ResolveRelativeAddress((PVOID)PiDDBLock, 3, 7);
	if (!PiDDBLock) {
		return 0;
	}
	
	return PiDDBLock;
}

PRTL_AVL_TABLE
GetPiDDBTable() {
	auto n = skCrypt("ntoskrnl.exe");
	NtosBaseInfo BaseInfo;
	PCHAR base = (PCHAR)Util::GetDriverBase(n, &BaseInfo);

	auto PiDDBTablePattern = skCrypt(PIDDB_TABLE_PATTERN);
	auto PiDDBTableMask = skCrypt(PIDDB_TABLE_MASK);
	PVOID PiDDBCacheTablePtr = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, PiDDBTablePattern, PiDDBTableMask);
	PiDDBTablePattern.clear();
	PiDDBTableMask.clear();

	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)Memory::ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7); // 6 10

	if (!PiDDBCacheTable) {
		return 0;
	}

	return PiDDBCacheTable;
}

BOOL
VerifyPiDDB() {
	return (GetPiDDBLock() != 0 && GetPiDDBTable() != 0);
}

BOOL
CleanPiDDB(
	UNICODE_STRING DriverName
) {
	PERESOURCE PiDDBLock = GetPiDDBLock();
	PRTL_AVL_TABLE PiDDBCacheTable = GetPiDDBTable();

	PiDDBCacheTable->TableContext = (PVOID)1;
	PIDDBCACHE_ENTRY LookupEntry = { 0 };
	RtlInitUnicodeString(&LookupEntry.DriverName, L"MyDriver");
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
	PIDDBCACHE_ENTRY* pFoundEntry = (PIDDBCACHE_ENTRY*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &LookupEntry);
	if (pFoundEntry == NULL) {
		ExReleaseResourceLite(PiDDBLock);
		return FALSE;
	}
	RemoveEntryList(&pFoundEntry->List);
	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
	ExReleaseResourceLite(PiDDBLock);
	return TRUE;
}

BOOL
CleanKernelHashBucketList(
	UNICODE_STRING DriverName
) {
	auto CIDLLString = skCrypt("ci.dll");
	NtosBaseInfo BaseInfo;
	CONST PVOID CIDLLBase = Util::GetDriverBase(CIDLLString, &BaseInfo);
	CIDLLString.clear();

	if (!CIDLLBase) {
		return FALSE;
	}

	auto KernelBucketHashPattern = skCrypt(CI_DLL_KERNEL_HASH_BUCKET_PATTERN);
	auto KernelBucketHashMask = skCrypt(CI_DLL_KERNEL_HASH_BUCKET_MASK);
	CONST PVOID SignatureAddress = Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, KernelBucketHashPattern, KernelBucketHashMask);
	KernelBucketHashPattern.clear();
	KernelBucketHashMask.clear();
	if (!SignatureAddress) {
		return FALSE;
	}

	CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)Memory::ResolveRelativeAddress(SignatureAddress, 3, 7);
	if (!g_KernelHashBucketList) {
		return FALSE;
	}

	LARGE_INTEGER Time{};
	KeQuerySystemTimePrecise(&Time);

	BOOL Status = FALSE;
	for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
		CONST PWCHAR wsName = PWCH(i + 0x48);
		if (wcsstr(wsName, DriverName.Buffer)) {
			PUCHAR Hash = PUCHAR(i + 0x18);
			for (UINT j = 0; j < 20; j++)
				Hash[j] = UCHAR(RtlRandomEx(&Time.LowPart) % 255);

			Status = TRUE;
		}
	}

	return Status;
}

BOOL
DeleteRegistryKey(
	UNICODE_STRING RegistryPath
) {
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;

	InitializeObjectAttributes(&KeyAttributes, &RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes))) {
		return FALSE;
	}

	if (!NT_SUCCESS(ZwDeleteKey(KeyHandle))) {
		return FALSE;
	}

	return TRUE;
}

BOOL
DeleteFile(
	UNICODE_STRING FilePath
) {
	OBJECT_ATTRIBUTES FileAttributes;
	InitializeObjectAttributes(&FileAttributes, &FilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwDeleteFile(&FileAttributes))) {
		return FALSE;
	}

	return TRUE;
}





NTSTATUS Hide::HideEverything(UNICODE_STRING DriverName) {
	NTSTATUS Status = STATUS_SUCCESS;
	if (VerifyPiDDB()) {
		if (!CleanPiDDB(DriverName)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, skCrypt("Failed to clean PiDDB\n"));
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else {
		Log::Debug(skCrypt("Failed to verify piddb\n"));
		Status = STATUS_UNSUCCESSFUL;
	}

	if (VerifyMmu()) {
		if (!CleanMmu(DriverName)) {
			Log::Debug(skCrypt("Failed to clean mmu\n"));
			Status = STATUS_UNSUCCESSFUL;
		}
	}
	else {
		Log::Debug(skCrypt("Failed to verify mmu\n"));
		Status = STATUS_UNSUCCESSFUL;
	}


	if (CleanKernelHashBucketList(DriverName)) {
	}
	else {
		Log::Debug(skCrypt("failed to clean has bucket list\n"));
		Status = STATUS_UNSUCCESSFUL;
	}

	return Status;
}

BOOLEAN Hide::FindPoolTable(uintptr_t* PoolBigPageTable, SIZE_T* PoolBigPageTableSize, PVOID ModuleBase) {
	auto Pattern1 = skCrypt("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00");
	auto Mask1 = skCrypt("x????xxxx");

	PVOID ExProtectPoolExCallInstructionAdd = (PVOID)Util::FindPatternImage((PCHAR)ModuleBase, Pattern1, Mask1);
	Pattern1.clear();
	Mask1.clear();

	if (!ExProtectPoolExCallInstructionAdd) 
		return FALSE;

	PVOID ExProtectPoolAddress = Memory::ResolveRelativeAddress(ExProtectPoolExCallInstructionAdd, 1, 5);

	if (!ExProtectPoolAddress) 
		return FALSE;

	PVOID PoolBigPageTableInstructionAddress = (PVOID)((ULONG64)ExProtectPoolAddress + 0x95);
	*PoolBigPageTable = (uintptr_t)Memory::ResolveRelativeAddress(PoolBigPageTableInstructionAddress, 3, 7);


	PVOID PoolBigPageTableSizeInstructionAddress = (PVOID)((ULONG64)ExProtectPoolAddress + 0x8E);
	*PoolBigPageTableSize = (SIZE_T)Memory::ResolveRelativeAddress(PoolBigPageTableSizeInstructionAddress, 3, 7);


	return TRUE;
}

BOOLEAN Hide::NullPfn(PMDL mdl) {
	PPFN_NUMBER mdlPages = MmGetMdlPfnArray(mdl);
	if (!mdlPages) 
		return FALSE;

	ULONG MdlPageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG NullPfn = 0x0;

	MM_COPY_ADDRESS SrcAddress{ 0 };
	SrcAddress.VirtualAddress = &NullPfn;

	for (ULONG i = 0; i < MdlPageCount; i++) {
		size_t Bytes = 0;
		MmCopyMemory(&mdlPages[i], SrcAddress, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &Bytes);

	}


	return TRUE;
}

NTSTATUS Hide::Hide(PVOID BigPoolAddress) {
	NTSTATUS Status = STATUS_SUCCESS;


	NtosBaseInfo NtosInfo{ 0 };
	auto sDriverName = skCrypt("ntoskrnl.exe");
	Util::GetDriverBase(sDriverName, &NtosInfo);
	sDriverName.clear();
	if (!NtosInfo.BaseAddress) 
		return STATUS_UNSUCCESSFUL;

	uintptr_t pPoolBigPageTable = 0;
	SIZE_T pPoolBigPageTableSize = 0;
	ULONGLONG NumOfBytes = 0;

	if (FindPoolTable(&pPoolBigPageTable, &pPoolBigPageTableSize, NtosInfo.BaseAddress)) {

		PPOOL_TRACKER_BIG_PAGES PoolBigPageTable{ 0 };
		RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);
		SIZE_T PoolBigPageTableSize = 0;
		RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

		for (int i = 0; i < PoolBigPageTableSize; i++) {
			if (PoolBigPageTable[i].Va == (ULONGLONG)BigPoolAddress || PoolBigPageTable[i].Va == ((ULONGLONG)BigPoolAddress + 0x1)) {
				NumOfBytes = PoolBigPageTable[i].NumberOfBytes;
				PoolBigPageTable[i].Va = 0x1;
				PoolBigPageTable[i].NumberOfBytes = 0x0;
			}
		}
	}

	
	auto MDL = IoAllocateMdl(reinterpret_cast<PVOID>(BigPoolAddress), NumOfBytes, FALSE, FALSE, NULL);


	if (!NullPfn(MDL)) {
		return FALSE;
	}
	else {
		return TRUE;
	}
	


	return TRUE;
}