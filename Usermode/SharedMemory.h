#pragma once

#include "Driver.h"
#include "LazyImp.h"
#pragma warning(disable : 4996)

enum Status {
	Inactive,
	Active,
	Waiting,
	Exit
};

namespace SharedMemory {
	void PushQueue();

	void PopQueue();

	BOOL WriteSharedMemory(PVOID Address, PVOID Value, SIZE_T Size);

	BOOL SetStatus(Status Status);

	BOOL SetCode(DWORD Code);

	Status GetStatuss();

	DWORD GetCode();

	void Connect(CommunicationData InitData);

	void Disconnect();
		


	template <typename T>
	BOOL SendRequest(REQUEST_TYPE Request, T Data);

	template <typename T>
	BOOL SetBuffer(T Buffer);

	template <typename T>
	T ReadSharedMemory(PVOID Address, SIZE_T Size);


}

int GetProcID(const char* ProcName);

NTSTATUS GetLastThreadStack(ULONG_PTR ProcID, PVOID pOut, PVOID pThreadID);


NTSTATUS GetBase(PVOID pOut, PVOID pOutSize, const std::string DllName, HANDLE ProcessID);


NTSTATUS ReadMemory(IN const HANDLE Pid, IN const PVOID Address, IN const SIZE_T Size, OUT const PVOID pOut);

NTSTATUS WriteMemory(IN const HANDLE Pid, IN const DWORD64 Ptr, IN const ULONG Size, IN const PVOID pSrc);

NTSTATUS ProtectMemory(IN CONST HANDLE ProcessId, IN CONST PVOID Address, IN CONST ULONG NewProt, IN OUT CONST PVOID pInOutProtect, IN SIZE_T Size);

NTSTATUS AllocMemory(IN const HANDLE ProcessId, OUT const PVOID pOut, IN const SIZE_T Size, IN const ULONG_PTR Protect);

NTSTATUS FreeMemory(IN const HANDLE ProcessId, IN const PVOID Address);

NTSTATUS SetPte(IN const HANDLE ProcessId, IN const PVOID Address, IN const PTE_64 Pte);

NTSTATUS QueryVirtualMemory(IN const HANDLE ProcessId, IN const PVOID Address, OUT const PVOID pOut);

NTSTATUS RemoveVADNode(IN const HANDLE ProcessId, IN const PVOID Address);

NTSTATUS AllocateVAD(IN const HANDLE ProcessId, IN const PVOID Address, IN const ULONGLONG Size);


NTSTATUS CallDllMain(PVOID DllMain, uintptr_t ProcessID, PVOID AddressToSwap, PVOID pOldPtr);

NTSTATUS GetProcessBase(HANDLE ProcessID, PVOID pOut, PVOID pOutSize);

NTSTATUS SwapPointer(HANDLE ProcessID, PVOID Src, PVOID Dest, PVOID pOutOld);

uintptr_t AllocKernelMemory(SIZE_T Size, PVOID pOutMDL);
bool ExposeKernelMem(HANDLE ProcID, PVOID KernelAddress, SIZE_T Size);


