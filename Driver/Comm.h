#pragma once
#include "Util.h"
#include "SkCrypt.h"
#include "Memory.h"

#define NT_ADD_FONT_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40"
#define NT_ADD_FONT_MASK	"xxx????x????xxxxxx"

#define NT_FUNC_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0"
#define NT_FUNC_MASK "xxx????x????xxxx"


#define DATA_UNIQUE 0x4321


typedef struct _LAST_THREADSTACK {
	UINT_PTR ProcessID;
	UINT_PTR ThreadID;
	PVOID pOut;
}LAST_THREADSTACK, * PLAST_THREADSTACK;

typedef struct _GET_PROCID {
	PVOID pOut;
	const char* ProcName;
}GET_PROCID, * PGET_PROCID;

typedef struct _READ_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
	SIZE_T Size;
	PVOID pOut;
} READ_MEMORY, * PREAD_MEMORY;

typedef struct _WRITE_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
	ULONG Size;
	PVOID pSrc;
} WRITE_MEMORY, * PWRITE_MEMORY;

typedef struct _PROTECT_MEMORY {
	HANDLE ProcessID;
	PVOID AddressToProtect;
	PVOID OutOldProtect;
	ULONG NewProt;
	SIZE_T Size;
} PROTECT_MEMORY, * PPROTECT_MEMORY;


typedef struct _ALLOC_MEMORY {
	HANDLE ProcessId;
	PVOID pOut;
	ULONG Size;
	ULONG Protect;
} ALLOC_MEMORY, * PALLOC_MEMORY;

typedef struct _FREE_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
} FREE_MEMORY, * PFREE_MEMORY;

typedef struct _GET_PTE {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} GET_PTE, * PGET_PTE;

typedef struct _SET_PTE {
	HANDLE ProcessId;
	PVOID Address;
	PTE_64 Pte;
} SET_PTE, * PSET_PTE;

typedef struct _QUERY_VIRTUAL_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} QUERY_VIRTUAL_MEMORY, * PQUERY_VIRTUAL_MEMORY;

typedef struct _GET_PROCESS_BASE {
	HANDLE ProcessID;
	PVOID pOut;
	PVOID pOutSize;
}GET_PROCESS_BASE, *PGET_PROCESS_BASE;

typedef struct _REMOVE_VAD {
	HANDLE ProcessId;
	PVOID Address;
} REMOVE_VAD, * PREMOVE_VAD;

typedef struct _ALLOCATE_VAD {
	HANDLE ProcessId;
	PVOID Address;
	ULONGLONG Size;
	ULONG Protection;
} ALLOCATE_VAD, * PALLOCATE_VAD;

typedef struct _GET_BASE {
	HANDLE ProcessID;
	PVOID pOut;
	WCHAR DllName[260];
	PVOID pOutSize;
}GET_BASE, * PGET_BASE;

typedef struct _SWAP_POINTER {
	HANDLE ProcID;
	PVOID Dest;
	PVOID Src;
	PVOID pOld;
}SWAP_POINTER, * PSWAP_POINTER;

typedef struct _ALLOC_MDL {
	PVOID Address;
	uintptr_t Mdl;
	SIZE_T Size;
}ALLOC_MDL, *PALLOC_MDL;

typedef struct _EXPOSE_ {
	PVOID Address;
	HANDLE ProcID;
	SIZE_T Size;
}EXPOSE, PEXPOSE;

typedef enum _REQUEST_TYPE {
	REQUEST_READ_MEMORY,
	REQUEST_WRITE_MEMORY,
	REQUEST_PROTECT_MEMORY,
	REQUEST_ALLOC_MEMORY,
	REQUEST_FREE_MEMORY,
	REQUEST_QUERY_VIRTUAL_MEMORY,
	REQUEST_REMOVE_VAD_NODE,
	REQUEST_ALLOC_VAD,
	REQUEST_GET_LAST_THREADSTACK,
	REQUEST_GET_PROCID,
	REQUEST_SPOOF_PTE,
	REQUEST_REMOVE_HOOK,
	REQUEST_SWAP_POINTER,
	REQUEST_GET_BASE,
	REQUEST_FIND_PATATERN,
	REQUEST_GET_PROCESS_BASE,
	REQUEST_ALLOC_MDL,
	REQUEST_EXPOSE,
	COMPLETE
} REQUEST_TYPE;

typedef struct _REQUEST_DATA {
	ULONG Unique;
	REQUEST_TYPE Type;
	PVOID Arguments;
} REQUEST_DATA, * PREQUEST_DATA;

typedef struct CommData{
	unsigned long ProcID;
	PVOID SharedMem;
	unsigned long* pCode;
	SHORT* pStatus;
	unsigned long Magic;
};

typedef struct CommunicationData {
	HANDLE ProcID;
	REQUEST_TYPE RequestType;
	PVOID Arguments;
	ULONG Unique;
	PVOID Status;
	PVOID Code;
}COMM_DATA, *PCOMM_DATA;




enum Status {
	Inactive,
	Active,
	Waiting,
	Exit
};


namespace Globals {
	extern uintptr_t gNtosBase;
	extern PVOID gEnumDebugDeviceFunc;
	extern uintptr_t gActiveThreadOff;
	extern PEPROCESS gProcess;
	extern COMM_DATA gCommData;
}




namespace Comm {
	
	NTSTATUS Initialize();


	VOID Loop();

	VOID Respond();

	BYTE GetStatus();

	unsigned long GetCode();

	BOOLEAN SetCode();
	
	BOOLEAN SetStatus(Status NewStatus);

	BOOLEAN ReadSharedMemory(PVOID Address, PVOID Buffer, SIZE_T Size);
	


}

