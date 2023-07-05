#include "SharedMemory.h"

INT Queue{ 0 };
CommunicationData Data;

void SharedMemory::PushQueue() {
	Queue += 1;
}

void SharedMemory::PopQueue() {
	Queue -= 1;
}




template <typename T>
T SharedMemory::ReadSharedMemory(PVOID Address, SIZE_T Size) {
	T Ret{ 0 };
	memcpy(static_cast<PVOID>(&Ret), Address, Size);
	return Ret;
}



BOOL SharedMemory::WriteSharedMemory(PVOID Address, PVOID Value, SIZE_T Size) {
	return reinterpret_cast<BOOL>(memcpy(Address, Value, Size));
}

template <typename T>
BOOL SharedMemory::SetBuffer(T Buffer) {
	return WriteSharedMemory(Data.Arguments, &Buffer, sizeof(T));
}


BOOL SharedMemory::SetStatus(Status Status) {
	return WriteSharedMemory(Data.Status, &Status, sizeof(SHORT));
}

BOOL SharedMemory::SetCode(DWORD Code) {
	return WriteSharedMemory(Data.Code, &Code, sizeof(DWORD));
}


Status SharedMemory::GetStatuss() {
	return static_cast<Status>(ReadSharedMemory<SHORT>(Data.Status, sizeof(SHORT)));
}

DWORD SharedMemory::GetCode() {
	return ReadSharedMemory<DWORD>(Data.Code, sizeof(SHORT));
}


void SharedMemory::Connect(CommunicationData InitData) {
	Data = InitData;
	SetStatus(Active);
}

void SharedMemory::Disconnect() {
	SetStatus(Exit);
}

template <typename T>
BOOL SharedMemory::SendRequest(REQUEST_TYPE Request, T Data) {
	// setup the shared memory 
	try {


		SetBuffer<T>(Data);

		if (SetCode(Request) && SetStatus(Waiting)) {

			do {
				Sleep(1);
			} while (GetStatuss() != Inactive);
		}



		return TRUE;
	}
	catch (...) {
	}
}

int GetProcID(const char* ProcName) {
	GET_PROCID Message{ 0 };
	int pOut = 0;
	Message.pOut = &pOut;
	Message.ProcName = ProcName;

	if (SharedMemory::SendRequest<GET_PROCID>(REQUEST_GET_PROCID, Message)) {
		return pOut;
	}


	return 0;

}

NTSTATUS GetLastThreadStack(ULONG_PTR ProcID, PVOID pOut, PVOID pThreadID) {
	LAST_THREADSTACK Message{ 0 };
	Message.pOut = pOut;
	Message.ProcessID = ProcID;
	Message.ThreadID = (UINT_PTR)pThreadID;

	if (SharedMemory::SendRequest<LAST_THREADSTACK>(REQUEST_GET_LAST_THREADSTACK, Message)) {
		return 1;
	}


	return 0;
}



NTSTATUS GetBase(PVOID pOut, PVOID pOutSize, const std::string DllName, HANDLE ProcessID) {

	GET_BASE Message{ 0 };
	Message.pOut = pOut;
	Message.ProcessID = ProcessID;
	Message.pOutSize = pOutSize;

	std::wstring wstr = { std::wstring(DllName.begin(), DllName.end()) };

	memset(Message.DllName, 0, sizeof(WCHAR) * 260);
	wcscpy(Message.DllName, wstr.c_str());



	if (SharedMemory::SendRequest<GET_BASE>(REQUEST_GET_BASE, Message)) {
		return 1;
	}
}


NTSTATUS ReadMemory(IN const HANDLE Pid, IN const PVOID Address, IN const SIZE_T Size, OUT const PVOID pOut) {
	READ_MEMORY Message;
	Message.ProcessId = Pid;
	Message.Address = (DWORD64)Address;
	Message.Size = Size;
	Message.pOut = pOut;

	if (SharedMemory::SendRequest<READ_MEMORY>(REQUEST_READ_MEMORY, Message)) {
		return 1;
	}
}

NTSTATUS WriteMemory(IN const HANDLE Pid, IN const DWORD64 Ptr, IN const ULONG Size, IN const PVOID pSrc) {
	WRITE_MEMORY Message;
	Message.ProcessId = Pid;
	Message.Address = Ptr;
	Message.Size = Size;
	Message.pSrc = pSrc;

	if (SharedMemory::SendRequest<WRITE_MEMORY>(REQUEST_WRITE_MEMORY, Message)) {
		return 1;
	}
}

NTSTATUS ProtectMemory(IN CONST HANDLE ProcessId, IN CONST PVOID Address, IN CONST ULONG NewProt, IN OUT CONST PVOID pInOutProtect, IN SIZE_T Size) {
	PROTECT_MEMORY Message;
	Message.ProcessID = ProcessId;
	Message.AddressToProtect = Address;
	Message.NewProt = NewProt;
	Message.Size = Size;
	Message.OutOldProtect = pInOutProtect;

	if (SharedMemory::SendRequest<PROTECT_MEMORY>(REQUEST_PROTECT_MEMORY, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS AllocMemory(IN const HANDLE ProcessId, OUT const PVOID pOut, IN const SIZE_T Size, IN const ULONG_PTR Protect) {
	ALLOC_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.pOut = pOut;
	Message.Size = Size;
	Message.Protect = Protect;

	if (SharedMemory::SendRequest<ALLOC_MEMORY>(REQUEST_ALLOC_MEMORY, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS FreeMemory(IN const HANDLE ProcessId, IN const PVOID Address) {
	FREE_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;

	if (SharedMemory::SendRequest<FREE_MEMORY>(REQUEST_FREE_MEMORY, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS SetPte(IN const HANDLE ProcessId, IN const PVOID Address, IN const PTE_64 Pte) {
	SET_PTE Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.Pte = Pte;

	if (SharedMemory::SendRequest<SET_PTE>(REQUEST_SPOOF_PTE, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS QueryVirtualMemory(IN const HANDLE ProcessId, IN const PVOID Address, OUT const PVOID pOut) {
	QUERY_VIRTUAL_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.pOut = pOut;

	if (SharedMemory::SendRequest<QUERY_VIRTUAL_MEMORY>(REQUEST_QUERY_VIRTUAL_MEMORY, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS RemoveVADNode(IN const HANDLE ProcessId, IN const PVOID Address) {
	REMOVE_VAD Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;

	if (SharedMemory::SendRequest<REMOVE_VAD>(REQUEST_REMOVE_VAD_NODE, Message)) {
		return 1;
	}

	return 0;
}

NTSTATUS AllocateVAD(IN const HANDLE ProcessId, IN const PVOID Address, IN const ULONGLONG Size) {
	ALLOCATE_VAD Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.Size = Size;

	if (SharedMemory::SendRequest<ALLOCATE_VAD>(REQUEST_ALLOC_VAD, Message)) {
		return 1;
	}
	return 0;
}

NTSTATUS SwapPointer(HANDLE ProcessID, PVOID Src, PVOID Dest, PVOID pOutOld) {
	SWAP_POINTER Message;
	Message.Dest = Dest;
	Message.pOld = pOutOld;
	Message.ProcID = ProcessID;
	Message.Src = Src;
	if (SharedMemory::SendRequest<SWAP_POINTER>(REQUEST_SWAP_POINTER, Message)) {
		return 1;
	}

	return 0;
}

uintptr_t AllocKernelMemory(SIZE_T Size, PVOID pOutMDL) {
	uintptr_t AllocationMem{ 0 };
	ALLOC_MDL Message{ 0 };
	Message.Address = &AllocationMem;
	Message.Mdl = (uintptr_t)pOutMDL;
	Message.Size = Size;

	printf("Address sent -> %p\n", Message.Address);
	printf("Mdl Address being sent -> %p\n", Message.Mdl);
	printf("Size -> %d\n", Message.Size);

	if (SharedMemory::SendRequest<ALLOC_MDL>(REQUEST_ALLOC_MDL, Message)) {
		return AllocationMem;
	}
	
	return 0;
	
}

bool ExposeKernelMem(HANDLE ProcID, PVOID KernelAddress, SIZE_T Size) {
	EXPOSE Message{ 0 };



	Message.ProcID = ProcID;
	Message.Address = KernelAddress;
	Message.Size = Size;

	printf("EXPOSE Proc ID -> %d\n", Message.ProcID);
	printf("EXPOSE Address -> %p\n", Message.Address);
	printf("EXPOSE Size -> %d\n", Message.Size);



	if (SharedMemory::SendRequest<EXPOSE>(REQUEST_EXPOSE, Message)) {
		return 1;
	}


	return 0;
}





NTSTATUS GetProcessBase(HANDLE ProcessID, PVOID pOut, PVOID pOutSize) {
	GET_PROCESS_BASE Message{ 0 };
	Message.pOut = pOut;
	Message.ProcessID = ProcessID;
	Message.pOutSize = pOutSize;

	if (SharedMemory::SendRequest<GET_PROCESS_BASE>(REQUEST_GET_PROCESS_BASE, Message)) {
		return 1;
	}

	return 0;
}