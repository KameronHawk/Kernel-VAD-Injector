#include "Util.h"
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))





PVOID Util::GetDriverBase(IN const char* DriverName, OUT pNtosBaseInfo pModBaseInfo) {
	PVOID DriverBase = NULL;
	ULONG Size = NULL;

	if (ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH) {
		return NULL;
	}

	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, Size);
	if (!Modules) {
		return NULL;
	}

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, NULL))) {
		ExFreePool(Modules);
		return NULL;
	}

	for (int i = 0; i < Modules->NumberOfModules; i++) {
		CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
		if (stristr(CurrentModuleName, DriverName)) {
			pModBaseInfo->BaseAddress = Modules->Modules[i].ImageBase;
			break;
		}
	}

	ExFreePool(Modules);
	return pModBaseInfo->BaseAddress;
	
}

NTSTATUS Util::SearchPattern(IN PCUCHAR Pattern, IN UCHAR Wildcard, IN ULONG_PTR Len, IN const VOID* Base, IN ULONG_PTR Size, OUT PVOID* ppFound, int index) {

	ASSERT(ppFound != NULL && Pattern != NULL && Base != NULL);
	if (ppFound == NULL || Pattern == NULL || Base == NULL)
		return STATUS_ACCESS_DENIED; 
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < Size - Len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < Len; j++)
		{
			if (Pattern[j] != Wildcard && Pattern[j] != ((PCUCHAR)Base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)Base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;

	
}

BOOL Util::CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}
	return TRUE;
}

PVOID Util::FindPattern(PCHAR Base, DWORD Length, PCHAR Pattern, PCHAR Mask) {
	auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
	{
		for (auto x = buffer; *mask; pattern++, mask++, x++) {
			auto addr = *(BYTE*)(pattern);
			if (addr != *x && *mask != '?')
				return FALSE;
		}

		return TRUE;
	};

	for (auto x = 0; x < Length - strlen(Mask); x++) {

		auto addr = (PBYTE)Base + x;
		if (checkMask(addr, Pattern, Mask))
			return addr;
	}

	return NULL;
}

PVOID Util::FindPatternImage(PCHAR Base, PCHAR Pattern, PCHAR Mask) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (!memcmp(Section->Name, "PAGE", 4) || !memcmp(Section->Name, ".text", 5)) {
			Match = FindPattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}

BOOL Util::SpoofPTE(PVOID Address, HANDLE ProcessID) {
	MEMORY_BASIC_INFORMATION Mbi{ 0 };
	NTSTATUS Status = 0;
	Status = Memory::QueryVirtualMemory(ProcessID, Address, MemoryBasicInformation, &Mbi, sizeof(Mbi));
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}

	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId(ProcessID, &Process);
	if (NT_SUCCESS(Status)) {
		KAPC_STATE State;
		KeStackAttachProcess(Process, &State);

		for (ULONGLONG i = reinterpret_cast<ULONGLONG>(Mbi.BaseAddress);
			i < (reinterpret_cast<ULONGLONG>(Mbi.BaseAddress) + Mbi.RegionSize);
			i += 0x1000) {
			PTE_64* PTE{ 0 };
			Memory::GetPte(ProcessID, reinterpret_cast<PVOID>(i), &PTE);
			if (PTE && PTE->Present) {
				PTE->ExecuteDisable = 0;
			}
		}
		KeUnstackDetachProcess(&State);
	}

	


	return TRUE;
}

uintptr_t Util::FindPatternInsideDll(HANDLE ProcessID, uintptr_t BaseOfModule, const char* Signature, const char* mask) {

	size_t sig_length = strlen(mask);

	MEMORY_BASIC_INFORMATION MBI{ 0 };
	Memory::QueryVirtualMemory(ProcessID, (PVOID)BaseOfModule, MemoryBasicInformation, &MBI, sizeof(MBI));




	for (size_t i = 0; i < MBI.RegionSize - sig_length; i++)
	{
		BOOL found = 1;
		for (size_t j = 0; j < sig_length; j++)
			found &= mask[j] == '?' || Signature[j] == *((char*)BaseOfModule + i + j);

		if (found)
			return (uintptr_t)(char*)Signature + i;
	}

	return 0;
}

NTSTATUS Util::GetProcessBase(HANDLE ProcessID, PVOID pOut, PVOID pSizeOut) {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS Process;
	uintptr_t Size = 0;
	PsLookupProcessByProcessId(ProcessID, &Process);
	
	KeAttachProcess(Process);
	PVOID ProcBaseAddress = (PVOID)PsGetProcessSectionBaseAddress(Process);

	const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)ProcBaseAddress + reinterpret_cast<IMAGE_DOS_HEADER*>(ProcBaseAddress)->e_lfanew);

	Size = nt->OptionalHeader.SizeOfImage;

	KeDetachProcess();

	
	Memory::SafeCopy(pOut, &ProcBaseAddress, sizeof(ProcBaseAddress));
	Memory::SafeCopy(pSizeOut, &Size, sizeof(Size));

	return STATUS_SUCCESS;
}

PVOID Util::GetExportedFunction(const ULONGLONG Base, const CHAR* Name)
{
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);

	const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
	const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(Base + data_directory.VirtualAddress);

	const auto address_of_names = reinterpret_cast<ULONG*>(Base + export_directory->AddressOfNames);

	for (size_t i = 0; i < export_directory->NumberOfNames; i++)
	{
		const auto function_name = reinterpret_cast<const char*>(Base + address_of_names[i]);

		if (!_stricmp(function_name, Name))
		{
			const auto name_ordinal = reinterpret_cast<unsigned short*>(Base + export_directory->AddressOfNameOrdinals)[i];

			const auto function_rva = Base + reinterpret_cast<ULONG*>(Base + export_directory->AddressOfFunctions)[name_ordinal];
			return (PVOID)function_rva;
		}
	}

	return 0;
}

UCHAR Util::RandomNum() {

	PVOID Base = Util::GetDriverBase(skCrypt("ntoskrnl.exe"), NULL);

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(Util::GetExportedFunction((ULONGLONG)Base, skCrypt("MmGetSystemRoutineAddress")));

	UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlRandom");
	auto cRtlRandom = reinterpret_cast<decltype(&RtlRandom)>(cMmGetSystemRoutineAddress(&RoutineName));

	ULONG Seed = 1234765;
	ULONG Rand = cRtlRandom(&Seed) % 100;

	UCHAR RandInt = 0;

	if (Rand >= 101 || Rand <= -1)
		RandInt = 72;

	return (UCHAR)(Rand);
}

PVOID Util::PrintDriverNames() {
	PVOID DriverBase = NULL;
	ULONG Size = NULL;

	if (ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH) {
		return NULL;
	}

	PRTL_PROCESS_MODULES Modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, Size);
	if (!Modules) {
		return NULL;
	}

	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, NULL))) {
		ExFreePool(Modules);
		return NULL;
	}

	for (int i = 0; i < Modules->NumberOfModules; i++) {
		CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
	}

	ExFreePool(Modules);
	return NULL;

}

VOID Util::Sleep(INT ms) {
	LARGE_INTEGER li{ 0 };
	li.QuadPart = -10000;

	for (INT i{ 0 }; i < ms; i++) {
		KeDelayExecutionThread(KernelMode, FALSE, &li);
	}
}

HANDLE Util::Process::GetProcessIDByName(IN UNICODE_STRING ProcessName) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG size = NULL;
	HANDLE ProcessID = 0;
	status = ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &size);

	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		
		return NULL;
	}

	PSYSTEM_PROCESS_INFORMATION SysProcInfoPool = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!SysProcInfoPool) {
		
		return NULL;
	}
	
	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemProcessInformation, SysProcInfoPool, size, NULL))) {
		ExFreePool(SysProcInfoPool);
		return NULL;
	}
	for (PSYSTEM_PROCESS_INFORMATION SysProcInfo = SysProcInfoPool;; SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((char*)SysProcInfo + SysProcInfo->NextEntryOffset)) {
		if (RtlCompareUnicodeString(&ProcessName, &SysProcInfo->ImageName, TRUE) == 0) {
			ProcessID = SysProcInfo->UniqueProcessId;
			ExFreePool(SysProcInfoPool);
			return ProcessID;
		}

		if (!SysProcInfo->NextEntryOffset) {
			ExFreePool(SysProcInfoPool);
			break;
		}
	}
	if (SysProcInfoPool) { ExFreePool(SysProcInfoPool); }

	return ProcessID;


	
}

PVOID Util::Process::GetLastThreadStack(HANDLE ProcessID, PVOID pOut, PVOID pThreadID) {
	PVOID ThreadID = 0;
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);
	PVOID TebBases[100]{ 0 };
	GetThreadTEBs(ProcessID, TebBases, &ThreadID);
	PVOID StackLimits[100]{ 0 };
	for (int i = 0; i < 100; i++) {
		if (!TebBases[i])
			continue;
		NT_TIB TIB{ 0 };

		Memory::ReadVirtualMemory(ProcessID, TebBases[i], &TIB, sizeof(TIB));
		StackLimits[i] = TIB.StackLimit;
	}

	PVOID LastThreadStack = 0;
	for (int i = 0; i < 100; i++) {

		if (!StackLimits[i])
			continue;

		if (StackLimits[i] > LastThreadStack)
			LastThreadStack = StackLimits[i];
	}
	MEMORY_BASIC_INFORMATION MBI{};
	Memory::QueryVirtualMemory(ProcessID, LastThreadStack, MemoryBasicInformation, &MBI, sizeof(MBI));

	PVOID AllocationBase = (PVOID)((ULONGLONG)MBI.BaseAddress + MBI.RegionSize);
	Memory::SafeCopy(pOut, &AllocationBase, sizeof(pOut));
	Memory::SafeCopy(pThreadID, &ThreadID, sizeof(pThreadID));
	return STATUS_SUCCESS;
}

NTSTATUS Util::Process::GetThreadTEBs(HANDLE ProcessID, PVOID* TEBs, PVOID* ThreadID) {

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG size = NULL;

	status = ZwQuerySystemInformation(SystemExtendedProcessInformation, NULL, NULL, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH) {
		return NULL;
	}

	PSYSTEM_PROCESS_INFORMATION SysProcInfoPool = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(NonPagedPool, size);

	if (!SysProcInfoPool) {
		return NULL;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemExtendedProcessInformation, SysProcInfoPool, size, NULL))) {
		ExFreePool(SysProcInfoPool);
		return NULL;
	}
	PSYSTEM_PROCESS_INFORMATION FoundProcess{ 0 };
	if (!SysProcInfoPool) {
		return NULL;
	}

	for (PSYSTEM_PROCESS_INFORMATION SysProcInfo = SysProcInfoPool;; SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((char*)SysProcInfo + SysProcInfo->NextEntryOffset)) {
		if (SysProcInfo->UniqueProcessId == ProcessID) {
			FoundProcess = SysProcInfo;
			break;
		}

		if (!SysProcInfo->NextEntryOffset) {
			ExFreePool(SysProcInfoPool);
			break;
		}
	}
	


	if (FoundProcess) {


		for (int i = 0; i < 100; i++) {
			if (FoundProcess->Threads[i].TebBase == 0) {
				continue;
			}
			if (i > FoundProcess->NumberOfThreads) {
				break;
			}
			PETHREAD pThread;
			PsLookupThreadByThreadId(FoundProcess->Threads[i].ThreadInfo.ClientId.UniqueThread, &pThread);
			if (pThread) {
				PMY_PKTHREAD CurrThread{ 0 };
				CurrThread = (PMY_PKTHREAD)pThread;
			}

			TEBs[i] = FoundProcess->Threads[i].TebBase;
		}
	}

	*ThreadID = FoundProcess->Threads[3].ThreadInfo.ClientId.UniqueThread;

	if (SysProcInfoPool)
		ExFreePool(SysProcInfoPool);

	return STATUS_SUCCESS;
}

PVOID Util::Process::GetPTE(PVOID Address, HANDLE ProcessID) {

	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);


	CR3 ProcessCr3 = Memory::GetProcessCR3(Process);


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

	addr.QuadPart = ProcessCr3.AddressOfPageDirectory << PAGE_SHIFT;

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

	return (PT_ENTRY_64*)pte;
Exit:
	return FALSE;
}

NTSTATUS Util::Process::SetPte(HANDLE ProcessID, PVOID Address) {
	PEPROCESS Process;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessID, &Process))) {
		return STATUS_UNSUCCESSFUL;
	}

	KeAttachProcess(Process);
	CR3 cr3{};
	cr3.Flags = __readcr3();
	PTE_64* pte = { 0 };
	
	Memory::GetPte(ProcessID, Address, &pte);
	if (pte) {
		if (pte->Present) {
			pte->ExecuteDisable = 0;
		}
	}
	KeDetachProcess();
	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}

NTSTATUS Util::Process::RemoveVAD(HANDLE ProcessID, PVOID Address) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId(ProcessID, &Process);

	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)Process + 0x7D8/*VADROOT*/);
	PMMVAD_SHORT pVadShort = NULL;

	Status = Memory::VAD::FindVAD(Process, (ULONGLONG)Address, &pVadShort);

	if (NT_SUCCESS(Status)) {
		RtlAvlRemoveNode(pTable, reinterpret_cast<PMMADDRESS_NODE>(pVadShort));
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS Util::Process::FreeMemory(HANDLE ProcessID, PVOID AddressToFree) {
	NTSTATUS Status;
	PEPROCESS Process;
	Status = PsLookupProcessByProcessId(ProcessID, &Process);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	SIZE_T Size = 0x1000;
	KeAttachProcess(Process);
	Status = ZwFreeVirtualMemory(NtCurrentProcess(), &AddressToFree, &Size, MEM_RELEASE);
	if (!NT_SUCCESS(Status)) {
		KeDetachProcess();
		ObDereferenceObject(Process);
		return Status;
	}
	ObDereferenceObject(Process);
	KeDetachProcess();
	return Status;
}

NTSTATUS Util::Process::SwapPointer(HANDLE ProcessID, PVOID Destination, PVOID Source, PVOID pOutOld) {
	
	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);
	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	

	KeAttachProcess(Process);
	uintptr_t old = 0;

	*(PVOID*)&old = InterlockedExchangePointer((PVOID*)Source, (PVOID)Destination);

	

	if (!old) {
		KeDetachProcess();
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}
	KeDetachProcess();
	Memory::SafeCopy(pOutOld, (PVOID)&old, sizeof(pOutOld));

	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

PVOID Util::Process::GetDllBase(HANDLE ProcessID, PCWSTR DllName, bool is32Bit, PVOID OutSize) {

	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);
	PVOID DllBase = NULL;
	ULONG DllSize = NULL;
	UNICODE_STRING uDllName;
	RtlInitUnicodeString(&uDllName, DllName);

	if (!Process) {
		return NULL;
	}



	if (is32Bit) {
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
		if (!pPeb32) {
			return NULL;
		}

		for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
			pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
			pListEntry = (PLIST_ENTRY32)pListEntry->Flink) {
			PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
			UNICODE_STRING uniString;
			RtlInitUnicodeString(&uniString, (PWCH)pEntry->BaseDllName.Buffer);
			if (RtlCompareUnicodeString(&uniString, &uDllName, TRUE) == 0) {
				return (PVOID)pEntry->DllBase;
			}
		}
	}
	else {

		KeAttachProcess(Process);
		PPEB64 pPeb = GetProcessPeb(Process);

		if (!pPeb) {
			return NULL;
		}
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink) {

			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, &uDllName, TRUE) == 0) {
				DllBase = pEntry->DllBase;
				DllSize = pEntry->SizeOfImage;
				break;
			}
		}
	}
	KeDetachProcess();

	Memory::SafeCopy(OutSize, &DllSize, sizeof(ULONG));

	return DllBase;

}

PVOID Util::Process::GetModuleExport(PVOID pBase, PCHAR FunctionName) {
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG expSize = 0;
	ULONG_PTR pAddress = 0;

	ASSERT(pBase != NULL);
	if (pBase == NULL)
		return NULL;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	// 32 bit image
	else
	{
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	PUSHORT pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
	PULONG  pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
	PULONG  pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

	for (ULONG i = 0; i < pExport->NumberOfFunctions; ++i)
	{
		USHORT OrdIndex = 0xFFFF;
		PCHAR  pName = NULL;

		// Find by index
		if ((ULONG_PTR)FunctionName <= 0xFFFF)
		{
			OrdIndex = (USHORT)i;
		}
		// Find by name
		else if ((ULONG_PTR)FunctionName > 0xFFFF && i < pExport->NumberOfNames)
		{
			pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
			OrdIndex = pAddressOfOrds[i];
		}
		// Weird params
		else
			return NULL;

		if (strcmp(FunctionName, pName) == 0) {
			pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;
			break;
		}
	}

	return (PVOID)pAddress;
}

PPEB64 Util::Process::GetProcessPeb(PEPROCESS TargetProcess) {
	PPEB64 pPeb = (PPEB64)PsGetProcessPeb(TargetProcess);

	if (!pPeb) {
		return NULL;
	}

	return pPeb;
}

uintptr_t Util::Process::FindPattern(uintptr_t ModuleBase, const char* Pattern) {

	auto Pattern_ = Pattern;
	uintptr_t FirstmMatch = 0;

	if (!ModuleBase) {
		return 0;
	}

	const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ModuleBase + reinterpret_cast<IMAGE_DOS_HEADER*>(ModuleBase)->e_lfanew);

	for (uintptr_t current = ModuleBase; current < ModuleBase + nt->OptionalHeader.SizeOfImage; current++) {

		if (!*Pattern_) {
			return FirstmMatch;
		}

		if (*(BYTE*)Pattern_ == '\?' || *(BYTE*)current == get_byte(Pattern_)) {

			if (!FirstmMatch)
				FirstmMatch = current;

			if (!Pattern_[2])
				return FirstmMatch;

			if (*(WORD*)Pattern_ == '\?\?' || *(BYTE*)Pattern_ != '\?')
				Pattern_ += 3;
			else
				Pattern_ += 2;

		}
		else {
			Pattern_ = Pattern;
			FirstmMatch = 0;
		}

	}



	return 0;
}

uintptr_t Util::Process::BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
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

BOOL Util::Process::IsProcessOpen(HANDLE ProcessID) {

	PEPROCESS Process = 0;

	PsLookupProcessByProcessId(ProcessID, &Process);


	if (!Process) {
		ObDereferenceObject(Process);
		return FALSE;
	}


	ObDereferenceObject(Process);
	return TRUE;
}


BOOLEAN Util::ReadSharedMemory(PVOID Address, PVOID Buffer, SIZE_T Size, PEPROCESS Process)
{
	SIZE_T Bytes{ 0 };

	if (NT_SUCCESS(MmCopyVirtualMemory(Process, Address, IoGetCurrentProcess(), Buffer, Size, KernelMode, &Bytes)))
	{
		return TRUE;
	}
	return FALSE;
}

MDL_INFORMATION Util::AllocateMdlMem(SIZE_T Size) {
	MDL_INFORMATION Memory;
	PHYSICAL_ADDRESS lower, higher;
	lower.QuadPart = 0;
	higher.QuadPart = 0xffff'ffff'ffff'ffffULL;

	const auto Pages = (Size / PAGE_SIZE) + 1;

	const auto mdl = MmAllocatePagesForMdl(lower, higher, lower, Pages * (uintptr_t)0x1000);

	if (!mdl) {
		return { 0,0 };
	}

	const auto MappingStartAddy = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

	if (!MappingStartAddy) {
		return { 0,0 };
	}
	
	if (!NT_SUCCESS(MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE))) {
		return { 0,0 };
	}
	Memory.mdl = mdl;
	Memory.va = reinterpret_cast<uintptr_t>(MappingStartAddy);
	return Memory;

}

PVOID Util::AllocateKernelMemory(SIZE_T Size, uintptr_t* MDL) {
	const auto size = size_align(Size);

	auto memory = AllocateMdlMem(size);

	while (memory.va % 0x1000 != 0) {
		FreeMdlMemory(memory);
		memory = AllocateMdlMem(size);
	}


	*MDL = (uintptr_t)memory.mdl;
	return (void*)memory.va;

	
}

void Util::FreeMdlMemory(MDL_INFORMATION& Memory) {
	MmUnmapLockedPages(reinterpret_cast<void*>(Memory.va), Memory.mdl);
	MmFreePagesFromMdl(Memory.mdl);
	ExFreePool(Memory.mdl);
}

BOOL Util::ExposeKernelMemory(HANDLE ProcessID, uintptr_t KernelAddress, SIZE_T Size) {

	PEPROCESS Process;
	PsLookupProcessByProcessId(ProcessID, &Process);

	KeAttachProcess(Process);

	CR3 cr3{};
	cr3.Flags = __readcr3();

	for (uintptr_t Address = KernelAddress; Address <= KernelAddress + Size; Address += 0x1000) {
		const auto PageInfo = Util::GetPageInfo((PVOID)Address, cr3);
		PageInfo.PDE->Supervisor = 1;
		PageInfo.PDPTE->Supervisor = 1;
		PageInfo.PML4E->Supervisor = 1;


		if (!PageInfo.PDE || (PageInfo.PTE && !PageInfo.PTE->Present)) {
			continue;
		}
		else {
			PageInfo.PTE->Supervisor = 1;
		}


	}

	KeDetachProcess();

	return true;
}

PAGE_INFORMATION Util::GetPageInfo(PVOID Va, CR3 cr3) {

	ADDRESS_TRANSLATION_HELPER helper;
	UINT32 level;
	PML4E_64* pml4, * pml4e;
	PDPTE_64* pdpt, * pdpte;
	PDE_64* pd, * pde;
	PTE_64* pt, * pte;

	PAGE_INFORMATION info;

	helper.AsUInt64 = (uintptr_t)Va;

	PHYSICAL_ADDRESS pa;

	pa.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;

	pml4 = (PML4E_64*)MmGetVirtualForPhysical(pa);

	pml4e = &pml4[helper.AsIndex.Pml4];

	info.PML4E = pml4e;

	if (pml4e->Present == FALSE)
	{
		info.PTE = nullptr;
		info.PDE = nullptr;
		info.PDPTE = nullptr;

		goto end;
	}

	pa.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

	pdpt = (PDPTE_64*)MmGetVirtualForPhysical(pa);

	pdpte = &pdpt[helper.AsIndex.Pdpt];

	info.PDPTE = pdpte;

	if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
	{
		info.PTE = nullptr;
		info.PDE = nullptr;

		goto end;
	}

	pa.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

	pd = (PDE_64*)MmGetVirtualForPhysical(pa);

	pde = &pd[helper.AsIndex.Pd];

	info.PDE = pde;

	if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
	{
		info.PTE = nullptr;

		goto end;
	}

	pa.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

	pt = (PTE_64*)MmGetVirtualForPhysical(pa);

	pte = &pt[helper.AsIndex.Pt];

	info.PTE = pte;

	return info;

end:
	return info;


	
}

