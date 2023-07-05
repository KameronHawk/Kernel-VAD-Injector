#include "Memory.h"

PMMVAD_SHORT(*MiAllocateVad)(UINT_PTR Start, UINT_PTR End, LOGICAL Deletable) = NULL;
NTSTATUS(*MiInsertVadCharges)(PMMVAD_SHORT VAD, PEPROCESS Process) = NULL;
VOID(*MiInsertVad)(PMMVAD_SHORT Vad, PEPROCESS Process) = NULL;
NTSTATUS(*PspGetContext)(PETHREAD, PCONTEXT, int, int, int) = NULL;
NTSTATUS(*PsSuspendThreadInternal)(PETHREAD, PLONG) = NULL;
NTSTATUS(*PsResumeThreadInternal)(PETHREAD, PLONG) = NULL;
NTSTATUS(*PspSetContextThreadInternal)(PETHREAD, PCONTEXT, int, int, int) = NULL;
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)
namespace crt
{
	template <typename t>
	__forceinline int strlen(t str) {
		if (!str)
		{
			return 0;
		}

		t buffer = str;

		while (*buffer)
		{
			*buffer++;
		}

		return (int)(buffer - str);
	}

	bool strcmp(const char* src, const char* dst)
	{
		if (!src || !dst)
		{
			return true;
		}

		const auto src_sz = crt::strlen(src);
		const auto dst_sz = crt::strlen(dst);

		if (src_sz != dst_sz)
		{
			return true;
		}

		for (int i = 0; i < src_sz; i++)
		{
			if (src[i] != dst[i])
			{
				return true;
			}
		}

		return false;
	}
}



NTSTATUS Memory::ReadVirtualMemory(HANDLE ProcessID, PVOID AddressToRead, PVOID AddressToStoreInfo, SIZE_T Size) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(ProcessID, &Process);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	SIZE_T Result = 0;
	__try {

		Status = MmCopyVirtualMemory(
			Process,
			AddressToRead,
			PsGetCurrentProcess(),
			AddressToStoreInfo,
			Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS Memory::WriteVirtualMemory(HANDLE ProcessID, PVOID AddressToWrite, PVOID ValueToWrite, SIZE_T Size) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(ProcessID, &Process);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	SIZE_T Result = 0;

	__try {
		Status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			(PVOID)ValueToWrite,
			Process,
			(PVOID)AddressToWrite,
			Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
	}

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS Memory::AllocateMemory(HANDLE ProcessID, PVOID pOut, ULONG_PTR Protection, SIZE_T Size) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId(ProcessID, &Process);

	if (NT_SUCCESS(Status)) {
		PVOID Address{ 0 };
		KAPC_STATE APCState = {};
		KeStackAttachProcess(Process, &APCState);
		if (!NT_SUCCESS(Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &Size, MEM_COMMIT | MEM_RESERVE, Protection))) {
			return Status;
		}
		KeUnstackDetachProcess(&APCState);
		SafeCopy(pOut, &Address, sizeof(Address));

		ObDereferenceObject(Process);
	}



	return Status;
}

NTSTATUS Memory::ReadPhysicalAddress(UINT64 TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
	MM_COPY_ADDRESS AddressToRead = { 0 };
	AddressToRead.PhysicalAddress.QuadPart = TargetAddress;
	return MmCopyMemory(Buffer, AddressToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

NTSTATUS Memory::ProtectVirtualMemory(HANDLE ProcessID, PVOID Address, SIZE_T SizeOfMem, PVOID oldProtOut, ULONG NewProt, bool UseOldSize) {
	NTSTATUS Status = STATUS_SUCCESS;
	KAPC_STATE State;
	
	LONG oldProt = 0;
	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);
	MEMORY_BASIC_INFORMATION Mbi{ };

	QueryVirtualMemory(ProcessID, Address, MemoryBasicInformation, &Mbi, sizeof(Mbi));
	SIZE_T Size = Mbi.RegionSize;

	if (UseOldSize) {
		Size = SizeOfMem;
	}


	KeStackAttachProcess(Process, &State);
	if (!NT_SUCCESS(Status = ZwProtectVirtualMemory(NtCurrentProcess(), &Address, &Size, NewProt, &oldProt))) {
		KeUnstackDetachProcess(&State);
		return STATUS_UNSUCCESSFUL;
	}
	KeUnstackDetachProcess(&State);

	Memory::SafeCopy(oldProtOut, &oldProt, sizeof(oldProt));

	return Status;
}

NTSTATUS Memory::InitializeFuncs(){
	NtosBaseInfo BaseInfo = { 0 };
	auto sDriverName = skCrypt("ntoskrnl.exe");
	PVOID DriverBase = Util::GetDriverBase(sDriverName.decrypt(), &BaseInfo);


	auto skMiAllocateVad = skCrypt(MI_ALLOCATE_VAD_PATTERN);
	auto skMiAllocateVadMask = skCrypt(MI_ALLOCATE_VAD_MASK);
	MiAllocateVad = (PMMVAD_SHORT(*)(UINT_PTR, UINT_PTR, LOGICAL))Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, skMiAllocateVad, skMiAllocateVadMask);
	skMiAllocateVad.clear();
	skMiAllocateVadMask.clear();

	if (!MiAllocateVad) {
		return STATUS_UNSUCCESSFUL;
	}
	auto skMiInsertVadMask = skCrypt(MI_INSERT_VAD_MASK);
	auto skMiInsertVadPattern = skCrypt(MI_INSERT_VAD_PATTERN);
	MiInsertVad = (VOID(*)(PMMVAD_SHORT, PEPROCESS))Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, skMiInsertVadPattern, skMiInsertVadMask);
	skMiInsertVadMask.clear();
	skMiInsertVadPattern.clear();

	if (!MiInsertVad) {
		return STATUS_UNSUCCESSFUL;
	}
	
	auto skMiInsertVadChargesMask = skCrypt(MI_INSERT_VAD_CHANGES_MASK);
	auto skMiInsertVadChargesPattern = skCrypt(MI_INSERT_VAD_CHANGES_PATTERN);
	MiInsertVadCharges = (NTSTATUS(*)(PMMVAD_SHORT, PEPROCESS))Util::FindPatternImage((PCHAR)BaseInfo.BaseAddress, skMiInsertVadChargesPattern, skMiInsertVadChargesMask);
	skMiInsertVadChargesMask.clear();
	skMiInsertVadChargesPattern.clear();

	if (!MiInsertVadCharges) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

NTSTATUS Memory::QueryVirtualMemory(HANDLE ProcessID, PVOID AddressToQuery, MEMORY_INFORMATION_CLASS MemClass, PVOID AddressToStore, SIZE_T Size) {

	PEPROCESS Process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessID, &Process))) {
		return STATUS_UNSUCCESSFUL;
	}
	MEMORY_BASIC_INFORMATION Mbi{};

	KeAttachProcess(Process);
	ZwQueryVirtualMemory(NtCurrentProcess(), AddressToQuery, MemClass, &Mbi, Size, NULL);
	KeDetachProcess();

	SafeCopy(AddressToStore, &Mbi, sizeof(Mbi));


	return STATUS_SUCCESS;

	
}

CR3 Memory::GetProcessCR3(PEPROCESS Process) {

	CR3 _cr3 = ((*(CR3*)((BYTE*)Process + 0x28)));

	return _cr3;

}

BOOLEAN Memory::SafeCopy(PVOID Destination, PVOID Source, SIZE_T Size) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Source, PsGetCurrentProcess(), Destination, Size, KernelMode, &returnSize)) && returnSize == Size) {
		return TRUE;
	}

	return FALSE;


}

NTSTATUS Memory::GetPte(HANDLE ProcessID, PVOID Address, PTE_64** pOut) {
	CR3 HostCR3{};
	HostCR3.Flags = __readcr3();

	ADDRESS_TRANSLATION_HELPER Helper;
	UINT32 level;
	PT_ENTRY_64* finalEntry;
	PML4E_64* pml4;
	PML4E_64* pml4e;
	PDPTE_64* pdpt;
	PDPTE_64* pdpte;
	PDE_64* pd;
	PDE_64* pde;
	PTE_64* pt;
	PTE_64* pte;

	Helper.AsUInt64 = (UINT64)Address;

	PHYSICAL_ADDRESS    addr;

	addr.QuadPart = HostCR3.AddressOfPageDirectory << PAGE_SHIFT;

	pml4 = (PML4E_64*)MmGetVirtualForPhysical(addr);

	pml4e = &pml4[Helper.AsIndex.Pml4];

	if (pml4e->Present == FALSE)
	{
		finalEntry = (PT_ENTRY_64*)pml4e;
		goto Exit;
	}

	addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

	pdpt = (PDPTE_64*)MmGetVirtualForPhysical(addr);

	pdpte = &pdpt[Helper.AsIndex.Pdpt];

	if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
	{
		finalEntry = (PT_ENTRY_64*)pdpte;
		goto Exit;
	}

	addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

	pd = (PDE_64*)MmGetVirtualForPhysical(addr);

	pde = &pd[Helper.AsIndex.Pd];

	if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
	{
		finalEntry = (PT_ENTRY_64*)pde;
		goto Exit;
	}

	addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

	pt = (PTE_64*)MmGetVirtualForPhysical(addr);

	pte = &pt[Helper.AsIndex.Pt];
	*pOut = pte;


Exit:
	return FALSE;
}

NTSTATUS Memory::SetPte(PTE_64* PTE) {

	return 0;
}

PVOID Memory::ResolveRelativeAddress(PVOID Instruction, ULONGLONG OffsetOffset, ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolveAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolveAddr;
}

uintptr_t Memory::find_pattern(uintptr_t base, const char* pattern, const char* mask) {
	const PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	const PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
	{
		const PIMAGE_SECTION_HEADER section = &sections[i];

		if ((sections[i].Characteristics & IMAGE_SCN_CNT_CODE) && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
		{
			const auto match = find_pattern2(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);

			if (match)
			{
				return match;
			}
		}
	}

	return 0;
}

uintptr_t Memory::find_pattern2(uintptr_t base, size_t range, const char* pattern, const char* mask)
{
	const auto check_mask = [](const char* base, const char* pattern, const char* mask) -> bool
	{
		for (; *mask; ++base, ++pattern, ++mask)
		{
			if (*mask == 'x' && *base != *pattern)
			{
				return false;
			}
		}

		return true;
	};

	range = range - crt::strlen(mask);

	for (size_t i = 0; i < range; ++i)
	{
		if (check_mask((const char*)base + i, pattern, mask))
		{
			return base + i;
		}
	}

	return NULL;
}

PVOID Memory::GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class)
{
	unsigned long size = 32;
	char buffer[32];

	ZwQuerySystemInformation(information_class, buffer, size, &size);

	void* info = ExAllocatePoolZero(NonPagedPool, size, 7265746172);

	if (!info)
		return nullptr;

	if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size)))
	{
		ExFreePool(info);
		return nullptr;
	}

	return info;
}

uintptr_t Memory::GetKernelModule(const char* name)
{
	const auto to_lower = [](char* string) -> const char*
	{
		for (char* pointer = string; *pointer != '\0'; ++pointer)
		{
			*pointer = (char)(short)tolower(*pointer);
		}

		return string;
	};

	const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);

	if (!info)
		return NULL;

	for (size_t i = 0; i < info->NumberOfModules; ++i)
	{
		const auto& mod = info->Modules[i];



		if (crt::strcmp(to_lower_c((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0)
		{
			const void* address = mod.ImageBase;
			ExFreePool(info);
			return (uintptr_t)address;
		}
	}

	ExFreePool(info);
	return NULL;
}

uintptr_t Memory::find_pattern3(uintptr_t module_base, const char* pattern)
{
	auto pattern_ = pattern;
	uintptr_t first_match = 0;

	if (!module_base)
	{
		return 0;
	}

	const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + reinterpret_cast<IMAGE_DOS_HEADER*>(module_base)->e_lfanew);

	for (uintptr_t current = module_base; current < module_base + nt->OptionalHeader.SizeOfImage; current++)
	{
		if (!*pattern_)
		{
			return first_match;
		}

		if (*(BYTE*)pattern_ == '\?' || *(BYTE*)current == get_byte(pattern_))
		{
			if (!first_match)
				first_match = current;

			if (!pattern_[2])
				return first_match;

			if (*(WORD*)pattern_ == '\?\?' || *(BYTE*)pattern_ != '\?')
				pattern_ += 3;

			else
				pattern_ += 2;
		}
		else
		{
			pattern_ = pattern;
			first_match = 0;
		}
	}

	return 0;
}

NTSTATUS Memory::BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	PVOID base = (PVOID)GetKernelModule("win32k.sys");
	if (!base)
		return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status))
				*(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

			return status;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS Memory::BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

BOOLEAN Memory::WriteToReadOnly(PVOID Dst, PVOID Buff, SIZE_T Size) {
	PMDL Mdl = IoAllocateMdl(Dst, Size, FALSE, FALSE, 0);

	if (!Mdl)
		return FALSE;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

	auto MmMap = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	memcpy(MmMap, Buff, Size);

	MmUnmapLockedPages(MmMap, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);



	return TRUE;
}

NTSTATUS Memory::VAD::AllocateVAD(HANDLE ProcessID, PVOID Address, SIZE_T Size) { // size is size of our dll
	PEPROCESS Process = NULL;

	NTSTATUS Status = PsLookupProcessByProcessId(ProcessID, &Process);

	if (!NT_SUCCESS(Status)) 
		return STATUS_UNSUCCESSFUL;
	
	ULONGLONG Start = (ULONGLONG)Address;
	ULONGLONG End = (ULONGLONG)Address + Size;

	KeAttachProcess(Process);
	MEMORY_BASIC_INFORMATION MBI{};
	if (!NT_SUCCESS(QueryVirtualMemory(ProcessID, (PVOID)Start, MemoryBasicInformation, &MBI, sizeof(MBI)))) {
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT VAD = MiAllocateVad(Start, End, TRUE);
	if (!VAD) 
		return STATUS_UNSUCCESSFUL;

	_MMVAD_FLAGS* Flags = (_MMVAD_FLAGS*)&VAD->u.LongFlags;

	Flags->Protection = (6);
	Flags->NoChange = 0;

	if (!NT_SUCCESS(MiInsertVadCharges(VAD, Process))) {
		ExFreePool(VAD);
		return STATUS_UNSUCCESSFUL;
	}
	MiInsertVad(VAD, Process);

	KeDetachProcess();

	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}

NTSTATUS Memory::VAD::FindVAD(PEPROCESS Process, ULONG_PTR Address, PMMVAD_SHORT* pResult) {
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG_PTR vpnStart = Address >> PAGE_SHIFT;
	ASSERT(Process != NULL && pResult != NULL);

	if (Process == NULL || pResult == NULL) {
		return STATUS_INVALID_PARAMETER;
	}

	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)Process + 0x7D8/*vadroot*/);
	PMM_AVL_NODE pNode = (pTable->BalancedRoot);

	if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode) {
		*pResult = (PMMVAD_SHORT)pNode;
	}
	else {
		Status = STATUS_NOT_FOUND;
	}


	return Status;
}

TABLE_SEARCH_RESULT Memory::VAD::MiFindNodeOrParent(IN PMM_AVL_TABLE Table, IN ULONG_PTR StartingVpn, OUT PMMADDRESS_NODE* NodeOrParent) {
	PMMADDRESS_NODE Child;
	PMMADDRESS_NODE NodeToExamine;
	PMMVAD_SHORT    VpnCompare;
	ULONG_PTR       startVpn;
	ULONG_PTR       endVpn;

	if (Table->NumberGenericTableElements == 0) {
		return TableEmptyTree;
	}

	NodeToExamine = (PMMADDRESS_NODE)(Table->BalancedRoot);

	for (;;) {

		VpnCompare = (PMMVAD_SHORT)NodeToExamine;
		startVpn = VpnCompare->StartingVpn;
		endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
		startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

		//
		// Compare the buffer with the key in the tree element.
		//

		if (StartingVpn < startVpn) {

			Child = NodeToExamine->LeftChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsLeft;
			}
		}
		else if (StartingVpn <= endVpn) {

			//
			// This is the node.
			//

			*NodeOrParent = NodeToExamine;
			return TableFoundNode;
		}
		else {

			Child = NodeToExamine->RightChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsRight;
			}
		}

	};
}
