#pragma once
#include <Windows.h>
#include <iostream>
#include "Hijack.h"
#include <TlHelp32.h>
#include <filesystem>
#include <vector>

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQueryInformationThread) (
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );


PVOID GetDllFromFile(LPCSTR DllPath);

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image);

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc);

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head);

BOOL resolve_import(PVOID p_local_img, PIMAGE_NT_HEADERS nt_head);

void write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head, HANDLE ProcessID);

void erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head, HANDLE ProcessID);


BOOL FlipExecuteBit(HANDLE ProcessID, PVOID Address, LONGLONG NX);


VOID Inject(PVOID DllImage);

void CloseDiscord();

bool OpenDiscord();

bool IsDiscordOpen();



