#include <iostream>
#include "Memory.h"
#include <string>

#include "sdk.h"



int main() {
	



	

	HANDLE col;
	col = GetStdHandle(STD_OUTPUT_HANDLE);
	
	SetConsoleTextAttribute(col, 10);

	printf(skCrypt("[*] Loading DLL..\n"));
	PVOID DllImage = GetDllFromFile(skCrypt("HelloWorld.dll"));

	if (!DllImage) {
		printf(skCrypt("[-] Failed to get local DLL... press any key to exit\n"));
		getchar();
		return 0;
	}
	else {
		Client::Connect();
		printf(skCrypt("[*] Loaded DLL!\n"));
		printf(skCrypt("[*] Launch Game Now\n"));
		printf(skCrypt("[*] When MOTD appears click ENTER.....\n"));
		getchar();

		Sleep(3000);
		Inject(DllImage);
	}

	

	SharedMemory::SetStatus(Exit);

	getchar();

	
	return 0;
}