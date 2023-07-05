#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include "Logs.h"
#include "Util.h"
#include "Comm.h"
#include "hide.h"






PVOID pPoolBase = NULL;
VOID MyUnloadDriver(PDRIVER_OBJECT DriverObject) {

}

#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

VOID NTAPI Main() {
	

	UNICODE_STRING DriverName;
	RtlInitUnicodeString(&DriverName, L"MyDriver");

	if (NT_SUCCESS(Hide::HideEverything(DriverName))) {
		Log::Success(skCrypt("Hid everything!\n"));
	}
	else {
		Log::Error(skCrypt("Failed to hide stuff\n"));
	}
	
	
	NTSTATUS Status = Memory::InitializeFuncs();
	if (NT_SUCCESS(Status)) {
		Log::Success(skCrypt("great found addresses needed!\n"));
	}
	else {
		Log::Error(skCrypt(" didnt find func addresses.\n"));
	}
	if (!NT_SUCCESS(Comm::Initialize())) {
		Log::Debug(skCrypt("failed to initalize communication\n\n"));

	}
	else {
		Log::Success(skCrypt("try to communicate now\n\n"));
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	HANDLE ThreadHandle = NULL;
	PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)Main, NULL);
	ZwClose(ThreadHandle);
	return STATUS_SUCCESS;
}
