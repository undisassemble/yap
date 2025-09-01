/*!
 * @file util.cpp
 * @author undisassemble
 * @brief Utility functions
 * @version 0.0.0
 * @date 2025-08-31
 * @copyright MIT License
 */

#include "util.hpp"

bool SaveProject() {
	if (!Data.Project[0]) return false;
	if (Data.Project[0] == ' ') {
		LOG(Info, MODULE_YAP, "No project file is selected.\n");
		return true;
	}

	// Check file ending
	char* ending = &Data.Project[lstrlenA(Data.Project) - 7];
	if ((lstrlenA(Data.Project) < 7 || lstrcmpA(ending, ".yaproj")) && lstrlenA(Data.Project) < sizeof(Data.Project) - 8) {
		memcpy(ending + 7, ".yaproj", 8);
	}

	// Open file
	HANDLE hFile = CreateFileA(Data.Project, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to save project", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Failed to save project: %d\n", GetLastError());
		return false;
	}

	// Write sig + version
	WriteFile(hFile, "YAP", 3, NULL, NULL);
	DWORD ver = __YAP_CONFIG_VERSION__;
	WriteFile(hFile, &ver, sizeof(DWORD), NULL, NULL);

	// Write data
	WriteFile(hFile, &Options, sizeof(Options_t), NULL, NULL);
	
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Saved project to %s\n", Data.Project);
	return true;
}

bool LoadProject() {
	char sig[3] = { 0 };
	DWORD ver = 0;

	// Open file
	HANDLE hFile = CreateFileA(Data.Project, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to load project", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Failed to load project: %d\n", GetLastError());
		Data.Project[0] = 0;
		return false;
	}

	// Read signature
	ReadFile(hFile, sig, 3, NULL, NULL);
	if (memcmp(sig, "YAP", 3)) {
		Modal("Invalid/corrupt project", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Invalid/corrupt project\n");
		CloseHandle(hFile);
		Data.Project[0] = 0;
		return false;
	}

	// Read version
	ReadFile(hFile, &ver, sizeof(DWORD), NULL, NULL);
	if (ver != __YAP_CONFIG_VERSION__) {
		Modal("Version mismatch", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Version mismatch\n");
		LOG(Info, MODULE_YAP, "Current version: %d\n", __YAP_CONFIG_VERSION__);
		LOG(Info, MODULE_YAP, "Project version: %d\n", ver);
		CloseHandle(hFile);
		Data.Project[0] = 0;
		return false;
	}

	// Read data
	ReadFile(hFile, &Options, sizeof(Options_t), NULL, NULL);
	
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Loaded %s\n", Data.Project);
	return true;
}

uint64_t rand64() {
	uint64_t ret = rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	return ret;
}

void LOG(LoggingLevel_t level, const char* mod, const char* str, ...) {
	va_list args;
	va_start(args, str);
	vLOG(level, mod, str, args);
	va_end(args);
}

void vLOG(LoggingLevel_t level, const char* mod, const char* str, va_list vargs) {
	char buffer[1024];
	vsnprintf(buffer, sizeof(buffer), str, vargs);
	if (Data.bUsingConsole) {
		if (level) {
			switch (level) {
			case Failed:
				WriteConsoleA(hStdOut, LOG_ERROR "[", sizeof(LOG_ERROR), NULL, NULL);
				break;
			case Success:
				WriteConsoleA(hStdOut, LOG_SUCCESS "[", sizeof(LOG_SUCCESS), NULL, NULL);
				break;
			case Warning:
				WriteConsoleA(hStdOut, LOG_WARNING "[", sizeof(LOG_WARNING), NULL, NULL);
				break;
			case Info:
				WriteConsoleA(hStdOut, LOG_INFO "[", sizeof(LOG_INFO), NULL, NULL);
			}
			WriteConsoleA(hStdOut, mod, strlen(mod), NULL, NULL);
			WriteConsoleA(hStdOut, "]: \t", 4, NULL, NULL);
		}
		WriteConsoleA(hStdOut, buffer, lstrlenA(buffer), NULL, NULL);
	}

	if (hLogFile) {
		if (level) {
			switch (level) {
			case Failed:
				WriteFile(hLogFile, "[-] [", 5, NULL, NULL);
				break;
			case Success:
				WriteFile(hLogFile, "[+] [", 5, NULL, NULL);
				break;
			case Warning:
				WriteFile(hLogFile, "[*] [", 5, NULL, NULL);
				break;
			case Info:
				WriteFile(hLogFile, "[?] [", 5, NULL, NULL);
			}
			WriteFile(hLogFile, mod, strlen(mod), NULL, NULL);
			WriteFile(hLogFile, "]: \t", 4, NULL, NULL);
		}
		WriteFile(hLogFile, buffer, strlen(buffer), NULL, NULL);
	}
}