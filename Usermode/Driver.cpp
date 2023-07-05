#include "Driver.h"

PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);







NTSTATUS InitalizeComms() {

	auto Module = LoadLibrary("ntdll.dll");

	if (!Module) {
		printf("Failed to get module\n");
		return STATUS_ACCESS_VIOLATION;
	}
	printf("Finding function now\n");


	*reinterpret_cast<PVOID*>(&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = GetProcAddress(Module, "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter");

	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		printf("Failed to get import\n\n");
		return STATUS_ACCESS_VIOLATION;
	}
	return 1;
}


