#pragma once

#include "SharedMemory.h"

PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounterr)(PVOID, PVOID, PVOID, PVOID);

SHORT gCode = 0;
SHORT gStatus = 0;



namespace Client {
	void KernelThread(PVOID LParam) {
		INT64 Status{ 0 };
		
		CommunicationData Data{ *(CommunicationData*)LParam };

		auto DataPtr = &Data;

		HMODULE Module{ LoadLibrary("ntdll.dll") };

		if (!Module) {
			printf("Failed to load ntdll\n");
			return;
		}
		*(PVOID*)&NtConvertBetweenAuxiliaryCounterAndPerformanceCounterr = GetProcAddress(Module, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");

		NtConvertBetweenAuxiliaryCounterAndPerformanceCounterr(0, &DataPtr, &Status, NULL);

	}


	void Connect() {
		COMM_DATA Data{ 0 };

		PVOID Memory{ VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };


		if (!Memory) {
			printf("Failed to alloc memory\n");
			return;
		}

		Data.ProcID = (HANDLE)GetCurrentProcessId();
		Data.Arguments = Memory;
		Data.Code = &gCode;
		Data.Status = &gStatus;
		Data.Unique = DATA_UNIQUE;


		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)KernelThread, &Data, 0, NULL);

		Sleep(500);


		SharedMemory::Connect(Data);
	}



	
}

