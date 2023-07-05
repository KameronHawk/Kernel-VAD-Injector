#include "Comm.h"

#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))
#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)

INT64 (NTAPI* EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);

uintptr_t gNtosBase = 0;
PVOID gEnumDebugDeviceFunc = nullptr;
uintptr_t gActiveThreadOff = 0;
PEPROCESS gProcess = nullptr;
COMM_DATA gCommData{0};


__int64 NTAPI Comms(PVOID Request, PINT64 Status)
{
	REQUEST_DATA Data{0};


	if (!Memory::SafeCopy(&gCommData, Request, sizeof(gCommData)) || gCommData.Unique != DATA_UNIQUE)
	{
		return EnumerateDebuggingDevicesOriginal(Request, Status);
	}


	InterlockedExchangePointer(static_cast<volatile PVOID*>(gEnumDebugDeviceFunc),
		(PVOID)EnumerateDebuggingDevicesOriginal);

	Comm::Loop();

	*Status = STATUS_NOT_IMPLEMENTED;
	return 0;
}


NTSTATUS Comm::Initialize()
{
	auto Base = (PCHAR)Memory::GetKernelModule(skCrypt("ntoskrnl.exe"));

	auto xKdEnumerateDebuggingDevicesPattern = skCrypt(NT_ADD_FONT_PATTERN);
	auto xKdEnumerateDebuggingDevicesMask = skCrypt(NT_ADD_FONT_MASK);
	PBYTE FunctionAddress = static_cast<PBYTE>(Util::FindPatternImage(Base, xKdEnumerateDebuggingDevicesPattern,
	                                                                  xKdEnumerateDebuggingDevicesMask));
	xKdEnumerateDebuggingDevicesPattern.clear();
	xKdEnumerateDebuggingDevicesMask.clear();
	if (!FunctionAddress)
	{
		return STATUS_UNSUCCESSFUL;
	}

	gEnumDebugDeviceFunc = RELATIVE_ADDR(FunctionAddress, 7);
	*(PVOID*)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer(
		static_cast<volatile PVOID*>(RELATIVE_ADDR(FunctionAddress, 7)), (PVOID)Comms);


	return STATUS_SUCCESS;
}


VOID Comm::Loop()
{
	PsLookupProcessByProcessId((HANDLE)gCommData.ProcID, &gProcess);

	if (gProcess == nullptr)
		return;

	for (;;)
	{
		if (*(DWORD*)((BYTE*)gProcess + gActiveThreadOff) == 1)
		{
			ObfDereferenceObject(gProcess);
			return;
		}

		DWORD Status = GetStatus();

		switch (Status)
		{
		case Inactive:
			{
				Util::Sleep(5);
			}
			break;

		case Active:
			{
				Util::Sleep(1);
			}
			break;

		case Waiting:
			{
				Respond();
			}
			break;

		case Exit:
			{
				SetStatus(Inactive);
				ObfDereferenceObject(gProcess);
				return;
			}
			break;


		default:
			{
				Util::Sleep(50);
			}
			break;
		}
	}
}



VOID Comm::Respond()
{
	DWORD Code = GetCode();

	switch (Code)
	{
	case REQUEST_READ_MEMORY:
		{
			
		
			READ_MEMORY ReadMem{nullptr};
			if (!Memory::SafeCopy(&ReadMem, gCommData.Arguments, sizeof(ReadMem)))
			{
				break;
			}

			if (!Util::Process::IsProcessOpen(ReadMem.ProcessId)) {
				SetStatus(Exit);
				break;
			}


			Memory::ReadVirtualMemory(ReadMem.ProcessId,
			                          ReadMem.Address,
			                          ReadMem.pOut,
			                          ReadMem.Size);
			SetStatus(Inactive);
		}break;


	case REQUEST_WRITE_MEMORY:
		{
		
		
			WRITE_MEMORY WriteMem{nullptr};
			if (!Memory::SafeCopy(&WriteMem, gCommData.Arguments, sizeof(WriteMem)))
			{
				return;
			}
			if (!Util::Process::IsProcessOpen(WriteMem.ProcessId)) {
				SetStatus(Exit);
				return;
			}

			if (!NT_SUCCESS(Memory::WriteVirtualMemory(WriteMem.ProcessId,
				WriteMem.Address,
				WriteMem.pSrc,
				WriteMem.Size))) {
				SetStatus(Inactive);
				return;
			}

			SetStatus(Inactive);
		}break;


	case REQUEST_SPOOF_PTE:
		{
		
			SET_PTE SetPte{nullptr};
			if (!Memory::SafeCopy(&SetPte, gCommData.Arguments, sizeof(SetPte)))
			{
			}

			if (!Util::Process::IsProcessOpen(SetPte.ProcessId)) {
				SetStatus(Exit);
				break;
			}



			Util::SpoofPTE(SetPte.Address, SetPte.ProcessId);
			SetStatus(Inactive);
		}break;


	case REQUEST_ALLOC_VAD:
		{
		
			ALLOCATE_VAD AllocVad{nullptr};
			if (!Memory::SafeCopy(&AllocVad, gCommData.Arguments, sizeof(AllocVad)))
			{
			}




			if (!Util::Process::IsProcessOpen(AllocVad.ProcessId)) {
				SetStatus(Exit);
				break;
			}

			Memory::VAD::AllocateVAD(AllocVad.ProcessId,
				AllocVad.Address,
				AllocVad.Size);


			

			SetStatus(Inactive);
		}break;


	case REQUEST_ALLOC_MEMORY:
		{
		
			ALLOC_MEMORY AllocMem{nullptr};
			if (!Memory::SafeCopy(&AllocMem, gCommData.Arguments, sizeof(AllocMem)))
			{
			}

			if (!Util::Process::IsProcessOpen(AllocMem.ProcessId)) {
				SetStatus(Exit);
				break;
			}


			Memory::AllocateMemory(AllocMem.ProcessId,
			                       AllocMem.pOut,
			                       AllocMem.Protect,
			                       AllocMem.Size);
			SetStatus(Inactive);
		}break;


	case REQUEST_GET_PROCID:
		{
		
			
			GET_PROCID ProcID{nullptr};


			if (!Memory::SafeCopy(&ProcID, gCommData.Arguments, sizeof(ProcID)))
			{
				return;
			}

			ANSI_STRING sProcName;
			UNICODE_STRING uPorcName;
			RtlInitAnsiString(&sProcName, ProcID.ProcName);
			RtlAnsiStringToUnicodeString(&uPorcName, &sProcName, TRUE);
			HANDLE ProcessID = Util::Process::GetProcessIDByName(uPorcName);
			Memory::SafeCopy(ProcID.pOut, &ProcessID, sizeof(ProcessID));
			SetStatus(Inactive);
		}break;


	case REQUEST_GET_LAST_THREADSTACK:
		{
		
			LAST_THREADSTACK LastThreadStack;
			if (!Memory::SafeCopy(&LastThreadStack, gCommData.Arguments, sizeof(LastThreadStack)))
			{
				return;
			}

			if (!Util::Process::IsProcessOpen((HANDLE)LastThreadStack.ProcessID)) {
				SetStatus(Exit);
				break;
			}


			Util::Process::GetLastThreadStack((HANDLE)LastThreadStack.ProcessID, LastThreadStack.pOut,
			                                  (PVOID)LastThreadStack.ThreadID);

			SetStatus(Inactive);
		}break;


	case REQUEST_QUERY_VIRTUAL_MEMORY:
		{
		
			QUERY_VIRTUAL_MEMORY QueryVA{nullptr};
			if (!Memory::SafeCopy(&QueryVA, gCommData.Arguments, sizeof(QueryVA)))
			{
			}

			if (!Util::Process::IsProcessOpen(QueryVA.ProcessId)) {
				SetStatus(Exit);
				break;
			}


			Memory::QueryVirtualMemory(QueryVA.ProcessId, QueryVA.Address, MemoryBasicInformation, QueryVA.pOut,
			                           sizeof(MEMORY_BASIC_INFORMATION));

			SetStatus(Inactive);
		}break;


	case REQUEST_REMOVE_VAD_NODE:
		{
		
			REMOVE_VAD RemoveVad{nullptr};
			if (!Memory::SafeCopy(&RemoveVad, gCommData.Arguments, sizeof(RemoveVad)))
			{
			}

			if (!Util::Process::IsProcessOpen(RemoveVad.ProcessId)) {
				SetStatus(Exit);
				break;
			}



			Util::Process::RemoveVAD(RemoveVad.ProcessId, RemoveVad.Address);

			SetStatus(Inactive);
		}break;


	case REQUEST_FREE_MEMORY:
		{
		
			FREE_MEMORY FreeMem{nullptr};
			if (!Memory::SafeCopy(&FreeMem, gCommData.Arguments, sizeof(FreeMem)))
			{
			}

			if (!Util::Process::IsProcessOpen(FreeMem.ProcessId)) {
				SetStatus(Exit);
				break;
			}



			Util::Process::FreeMemory(FreeMem.ProcessId, FreeMem.Address);


			SetStatus(Inactive);
		}break;


	case REQUEST_GET_PROCESS_BASE:
		{
		
			GET_PROCESS_BASE ProcBase{nullptr};
			if (!Memory::SafeCopy(&ProcBase, gCommData.Arguments, sizeof(ProcBase)))
			{
				return;
			}

			if (!Util::Process::IsProcessOpen(ProcBase.ProcessID)) {
				SetStatus(Exit);
				break;
			}



			Util::GetProcessBase(ProcBase.ProcessID, ProcBase.pOut, ProcBase.pOutSize);
			


			SetStatus(Inactive);
		}break;


	case REQUEST_SWAP_POINTER:
		{
		
			SWAP_POINTER Swap = {nullptr};
			if (!Memory::SafeCopy(&Swap, gCommData.Arguments, sizeof(Swap)))
				return;


			if (!Swap.Dest || !Swap.Dest || !Swap.ProcID)
				return;


			if (!Util::Process::IsProcessOpen(Swap.ProcID)) {
				SetStatus(Exit);
				break;
			}



			Util::Process::SwapPointer(Swap.ProcID, Swap.Dest, Swap.Src, Swap.pOld);
			SetStatus(Inactive);
		}break;


	case REQUEST_GET_BASE:
		{
		
			GET_BASE GetBase{nullptr};
			if (!Memory::SafeCopy(&GetBase, gCommData.Arguments, sizeof(GetBase)))
			{
			}

			if (!Util::Process::IsProcessOpen(GetBase.ProcessID)) {
				SetStatus(Exit);
				break;
			}


			uintptr_t Base = (uintptr_t)Util::Process::GetDllBase(GetBase.ProcessID, GetBase.DllName, FALSE, GetBase.pOutSize);
			Memory::SafeCopy(GetBase.pOut, &Base, sizeof(Base));

			SetStatus(Inactive);
		}break;


	case REQUEST_PROTECT_MEMORY:
		{
		
			PROTECT_MEMORY ProtectMem{nullptr};
			if (!Memory::SafeCopy(&ProtectMem, gCommData.Arguments, sizeof(ProtectMem)))
			{
			}

			bool UseOldSize = false;
			if (!ProtectMem.OutOldProtect)
				UseOldSize = true;



			if (!Util::Process::IsProcessOpen(ProtectMem.ProcessID)) {
				SetStatus(Exit);
				break;
			}

			Memory::ProtectVirtualMemory(ProtectMem.ProcessID, ProtectMem.AddressToProtect, ProtectMem.Size,
			                             ProtectMem.OutOldProtect, ProtectMem.NewProt, UseOldSize);


			SetStatus(Inactive);
		}break;
	case REQUEST_ALLOC_MDL:
	{
		
		ALLOC_MDL Data{ 0 };

		if (!Memory::SafeCopy(&Data, gCommData.Arguments, sizeof(Data))) {

		}
		uintptr_t mdl = 0;
		PVOID Address = Util::AllocateKernelMemory(Data.Size, &mdl);

		if (!Address)
			return;

		if (!mdl || !Address)
			return;
		// pass ADDRESS and MDL as address to this request
		Memory::SafeCopy(Data.Address, &Address, sizeof(Address));
		Memory::SafeCopy((PVOID)Data.Mdl, &mdl, sizeof(mdl));


		SetStatus(Inactive);
	}break;

	case REQUEST_EXPOSE:
	{
		
		EXPOSE Data{ 0 };
		if (!Memory::SafeCopy(&Data, gCommData.Arguments, sizeof(Data))) {
			return;
		}

		if (!Data.ProcID || !Data.Address || !Data.Size) {
			return;
		}

		if (!Util::ExposeKernelMemory(Data.ProcID, (uintptr_t)Data.Address, Data.Size)) {
			return;
		}

		SetStatus(Inactive);


	}break;
	}
}


unsigned long Comm::GetCode()
{
	DWORD CurrCode = 0;
	ReadSharedMemory(gCommData.Code, &CurrCode, sizeof(DWORD));
	return CurrCode;
}


BYTE Comm::GetStatus()
{
	BYTE Status{ 0 };
	ReadSharedMemory(gCommData.Status, &Status, sizeof(SHORT));
	return Status;
}


BOOLEAN Comm::ReadSharedMemory(PVOID Address, PVOID Buffer, SIZE_T Size)
{
	SIZE_T Bytes{ 0 };

	if (NT_SUCCESS(MmCopyVirtualMemory(gProcess, Address, IoGetCurrentProcess(), Buffer, Size, KernelMode, &Bytes)))
	{
		return TRUE;
	}
	return FALSE;
}


BOOLEAN Comm::SetCode()
{
	return Util::WriteSharedMemory<SHORT>(gCommData.Code, COMPLETE);
}


BOOLEAN Comm::SetStatus(Status NewStatus)
{
	return Util::WriteSharedMemory<SHORT>(gCommData.Status, NewStatus);
}
