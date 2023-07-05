#include "Memory.h"

#pragma comment(lib, "ntdll.lib")

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);





PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
	PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
	for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
		if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
			return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

	return NULL;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
	HMODULE h_module = LoadLibraryExA(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);
	uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);
	func_offset -= (uintptr_t)h_module;
	FreeLibrary(h_module);

	return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
	if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
	reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, p_local_img);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return true;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;
		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_head, p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	} return true;
}

BOOL resolve_import(PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);
	if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) return true;

	LPSTR module_name = NULL;
	while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
	{
		uintptr_t base_image;
		base_image = (uintptr_t)LoadLibraryA(module_name);

		if (!base_image)
			return false;

		PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);
		while (ih_data->u1.AddressOfData)
		{
			if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)ibn->Name);

			} ih_data++;
		} import_desc++;
	} return true;
}

void write_sections(PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head, HANDLE ProcessID)
{

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		Sleep(20);
		WriteMemory((HANDLE)ProcessID, ((uintptr_t)p_module_base + section->VirtualAddress), section->SizeOfRawData, (PVOID)((uintptr_t)local_image + section->PointerToRawData));
	}
}

void erase_discardable_sect(PVOID p_module_base, PIMAGE_NT_HEADERS nt_head, HANDLE ProcessID)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			WriteMemory(ProcessID, ((uintptr_t)p_module_base + section->VirtualAddress), section->SizeOfRawData, zero_memory);
			VirtualFree(zero_memory, 0, MEM_RELEASE);
		}
	}
}

BOOL FlipExecuteBit(HANDLE ProcessID, PVOID Address, LONGLONG NX) {

	PTE_64 Null{0};
	SetPte(ProcessID, Address, Null);

	return TRUE;

	
}

PVOID GetDllFromFile(LPCSTR DllPath) {
	HANDLE hDll = CreateFileA(DllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDll == INVALID_HANDLE_VALUE) {
		return NULL;
	}
		

	DWORD DllFileSize = GetFileSize(hDll, NULL);
	PVOID DllBuffer = VirtualAlloc(NULL, DllFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hDll, DllBuffer, DllFileSize, NULL, FALSE)) {
		VirtualFree(DllBuffer, 0, MEM_RELEASE);
		goto Exit;
	}

Exit:
	CloseHandle(hDll);
	return DllBuffer;
}

VOID Inject(PVOID DllImage) {

    PIMAGE_NT_HEADERS DllNtHead = RtlImageNtHeader(DllImage);


	//==========================================
    // get process id
	//==========================================
    ULONG ProcessID = GetProcID(skCrypt("GFXTest64.exe"));
	DWORD threadID;
	while (!ProcessID) {
		threadID = GetWindowThreadProcessId(FindWindowA("gfx_test", NULL), &ProcessID);//skCrypt("Call of Duty® HQ") "gfx_test"
		Sleep(10);
	}




	if (ProcessID) {

		//==========================================
		// FindAllocation Base
		//==========================================
		PVOID AllocationBase = 0;
		PVOID ThreadHandler = 0;
		printf(skCrypt("[*] Attempting to find spot for DLL...\n"));
		GetLastThreadStack(ProcessID, &AllocationBase, &ThreadHandler);
		
		
		//==========================================
		//		Allocate VAD in target process
		//==========================================
		if (AllocationBase) {
			printf(skCrypt("[*] Found good spot for DLL -> 0x%X\n"), AllocationBase);
			AllocateVAD((HANDLE)ProcessID, AllocationBase, DllNtHead->OptionalHeader.SizeOfImage);
		}
		else {
			printf(skCrypt("[-] Failed to allocate DLL into process... closing\n"));
			return;
		}
		printf(skCrypt("[*] Allocated Memory For DLL -> 0x%X\n"), AllocationBase);


		//==========================================
		//			Fix Relocation Image
		//==========================================
		if (!relocate_image((PVOID)AllocationBase, DllImage, DllNtHead)) {
			printf(skCrypt("[-] Failed to Relocate Image...\n"));
			SharedMemory::SetStatus(Exit);
			return;
		}

		printf(skCrypt("[*] Relocated DLL\n"));



		//==========================================
		//				Fix IAT
		//==========================================
		if (!resolve_import(DllImage, DllNtHead)) {
			printf(skCrypt("[-] Failed to fix Import Table...\n"));
			SharedMemory::SetStatus(Exit);
			return;
		}
		printf(skCrypt("[*] Fixed Import Table...\n"));


		//==========================================
		//				Write Sections
		//==========================================
		write_sections((PVOID)AllocationBase, DllImage, DllNtHead, (HANDLE)ProcessID);

		printf(skCrypt("[*] Wrote DLL memory to processID %d , 0x%X\n"), (HANDLE)ProcessID, AllocationBase);
		

		if (FlipExecuteBit((HANDLE)ProcessID, AllocationBase, 0)) {

			if (!Hijack::CallDllMain(ProcessID, (DWORD)threadID, (PVOID)AllocationBase, DllNtHead->OptionalHeader.AddressOfEntryPoint)) {
				SharedMemory::SetStatus(Exit);
				printf(skCrypt("[-] Something failed close game quickly....\n"));
				return;
			}
		}

		//==========================================
		//			Erase Discardable Sect
		//==========================================
		erase_discardable_sect((PVOID)AllocationBase, DllNtHead, (HANDLE)ProcessID);


		//some reason removing the vad leaves a page behind so we're gonna do it again then it works
		RemoveVADNode((HANDLE)ProcessID, AllocationBase);
		RemoveVADNode((HANDLE)ProcessID, AllocationBase);
		LI_FN(VirtualFree).get()(DllImage, 0, MEM_RELEASE);
		printf(skCrypt("[*] Hid DLL....\n"));
		SharedMemory::SetStatus(Exit);
	}
    


}

void CloseDiscord() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (stricmp(entry.szExeFile, skCrypt("discord.exe")) == 0)
			{

				printf(skCrypt("Discord Open, closing discord...\n"));
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);

				TerminateProcess(hProcess, 1);

				CloseHandle(hProcess);
				CloseHandle(snapshot);
				return;
			}
		}
	}
	printf(skCrypt("Discord not open...\n"));

	CloseHandle(snapshot);
}

bool OpenDiscord() {
	char pDirectoryPath[256]{ 0 };
	size_t size = sizeof(pDirectoryPath);
	PVOID DllBase = NULL;
	for (const auto& entry : std::filesystem::recursive_directory_iterator("C:\\Users")) {

		std::string CurrDir = entry.path().string();
		if (CurrDir.find(skCrypt("Discord.exe")) != std::string::npos) {
			char buff[256];
			sprintf(buff, "start %s", entry.path().string().c_str());
			printf(skCrypt("DiscordFound -> %s\n"), entry.path().string().c_str());
			system(buff);
			return true;
		}
	}

	return false;
}

bool IsDiscordOpen() {
	bool IsRunning = false;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (stricmp(entry.szExeFile, skCrypt("discord.exe")) == 0)
			{

				printf(skCrypt("Discord Re-Opened\n"));
				CloseHandle(snapshot);
				return true;
			}
		}
	}
	printf(skCrypt("Discord not open...\n"));

	CloseHandle(snapshot);
	return false;
}

