#pragma once
#include <ntifs.h>

namespace Log {
	inline void Debug(char* Message, ...) {
		va_list args;
		__va_start(&args, Message);
		vDbgPrintExWithPrefix("[DBG] ", 0, 0, Message, args);
	}

	inline void Success(char* Message, ...) {
		va_list args;
		__va_start(&args, Message);
		vDbgPrintExWithPrefix("[+] ", 0, 0, Message, args);
	}

	inline void Error(char* Message, ...) {
		va_list args;
		__va_start(&args, Message);
		vDbgPrintExWithPrefix("[ERR] ", 0, 0, Message, args);
	}

	inline void Info(char* Message, ...) {
		va_list args;
		__va_start(&args, Message);
		vDbgPrintExWithPrefix("[*] ", 0, 0, Message, args);
	}
};
