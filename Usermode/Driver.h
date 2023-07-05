#pragma once
#define DATA_UNIQUE 0x4321
#include "ia32.h"
#include "vad.h"
#include <iostream>
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)



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
	DWORD64 Address;
	SIZE_T Size;
	PVOID pOut;
} READ_MEMORY, * PREAD_MEMORY;

typedef struct _WRITE_MEMORY {
	HANDLE ProcessId;
	DWORD64 Address;
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
	DWORD Size;
	DWORD Protect;
} ALLOC_MEMORY, * PALLOC_MEMORY;

typedef struct _FREE_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
} FREE_MEMORY, * PFREE_MEMORY;


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

typedef struct _GET_VAD_FLAGS {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} GET_VAD_FLAGS, * PGET_VAD_FLAGS;

typedef struct _SET_VAD_FLAGS {
	HANDLE ProcessId;
	PVOID Address;
	MMVAD_FLAGS VADFlags;
} SET_VAD_FLAGS, * PSET_VAD_FLAGS;

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

typedef struct _SWAP_POINTER {
	HANDLE ProcID;
	PVOID Dest;
	PVOID Src;
	PVOID pOld;
}SWAP_POINTER, * PSWAP_POINTER;

typedef struct _GET_BASE {
	HANDLE ProcessID;
	PVOID pOut;
	WCHAR DllName[260];
	PVOID pOutSize;
}GET_BASE, * PGET_BASE;

typedef struct _PATTERN_REQUEST {
	HANDLE ProcessID;
	uintptr_t Base;
	PVOID Address;
	const char* signature;
	const char* mask;
}PATTERN_REQUEST, * PPATTERN_REQUEST;

typedef struct _GET_PROCESS_BASE {
	HANDLE ProcessID;
	PVOID pOut;
	PVOID pOutSize;
}GET_PROCESS_BASE, * PGET_PROCESS_BASE;

typedef struct _ALLOC_MDL {
	PVOID Address;
	uintptr_t Mdl;
	SIZE_T Size;
}ALLOC_MDL, * PALLOC_MDL;

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
	DWORD Unique;
	REQUEST_TYPE Type;
	PVOID Arguments;
} REQUEST_DATA, * PREQUEST_DATA;


typedef struct CommunicationData {
	HANDLE ProcID;
	REQUEST_TYPE RequestType;
	PVOID Arguments;
	ULONG Unique;
	PVOID Status;
	PVOID Code;
}COMM_DATA, * PCOMM_DATA;








NTSTATUS InitalizeComms();



