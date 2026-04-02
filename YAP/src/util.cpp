/*!
 * @file util.cpp
 * @author undisassemble
 * @brief Utility functions
 * @version 0.0.0
 * @date 2026-04-02
 * @copyright MIT License
 */

#include "util.hpp"

std::unordered_map<std::string_view, std::variant<bool, int, Buffer, uint64_t>> config;
std::unordered_map<std::string_view, std::variant<bool, int>> settings;

namespace ConfigTypes {
	const BYTE Unknown = 0;
	const BYTE Bool = 1;
	const BYTE Int = 2;
	const BYTE Buffer = 3;
	const BYTE UInt64 = 4;
};

bool LoadSettings() {
	settings["Style.iGradientAngle"] = 60;
	settings["Style.Accent.iR"] = 88;
	settings["Style.Accent.iG"] = 46;
	settings["Style.Accent.iB"] = 122;
	settings["Style.Accent.iIntensity"] = 60;
	settings["Style.bPartyMode"] = false;
	
	// TODO: Load from a file
	return true;
}

void LoadDefaultConfig() {
	config["Packing.bEnabled"] = false;
	config["Packing.bAntiDump"] = false;
	config["Packing.bEnableMasquerade"] = false;
	config["Packing.bNukeHeaders"] = false;
	config["Packing.bMitigateSideloading"] = false;
	config["Packing.bOnlyLoadMicrosoft"] = false;
	config["Packing.bMarkCritical"] = false;
	config["Packing.bAntiDebug"] = false;
	config["Packing.bAntiPatch"] = false;
	config["Packing.bAntiVM"] = false;
	config["Packing.bAllowHyperV"] = true;
	config["Packing.bAntiSandbox"] = false;
	config["Packing.bHideIAT"] = false;
	config["Packing.bAPIEmulation"] = false;
	config["Packing.bDelayedEntry"] = false;
	config["Packing.bDontCompressRsrc"] = true;
	config["Packing.bDirectSyscalls"] = false;
	config["Packing.bPartialUnpacking"] = false;
	config["Packing.iCompressionLevel"] = 5;
	config["Packing.iImmitate"] = YAP;
	if (!config.contains("Packing.sMasquerade")) config["Packing.sMasquerade"] = Buffer(MAX_PATH);
	memcpy(std::get<Buffer>(config["Packing.sMasquerade"]).Data(), "C:\\Windows\\System32\\cmd.exe", 28);
	config["Packing.sMessage"] = Buffer(64);
	config["Packing.iMutationLevel"] = 3;
	config["Packing.iEncodingCounts"] = 1;

	config["Reassembly.bEnabled"] = false;
	config["Reassembly.bRemoveData"] = false;
	config["Reassembly.bStrip"] = false;
	config["Reassembly.bStripDOSStub"] = false;
	config["Reassembly.bSubstitution"] = false;
	config["Reassembly.iMutationLevel"] = 0;
	
	config["Advanced.u64Rebase"] = (uint64_t)0;
	config["Advanced.bTrueRandomSecNames"] = false;
	config["Advanced.bSemiRandomSecNames"] = true;
	config["Advanced.bFakeSymbols"] = true;
	config["Advanced.bMutateAssembly"] = true;
	config["Advanced.bEnableSubstitution"] = true;
	config["Advanced.iUPXVersionMajor"] = 5;
	config["Advanced.iUPXVersionMinor"] = 1;
	config["Advanced.iUPXVersionPatch"] = 1;
	if (!config.contains("Advanced.sSec1Name")) config["Advanced.sSec1Name"] = Buffer(9);
	if (!config.contains("Advanced.sSec2Name")) config["Advanced.sSec2Name"] = Buffer(9);

	config["Debug.bDumpAsm"] = false;
	config["Debug.bDumpSections"] = false;
	config["Debug.bDumpFunctions"] = false;
	config["Debug.bGenerateBreakpoints"] = false;
	config["Debug.bGenerateMarks"] = false;
	config["Debug.bDisableRelocations"] = false;
	config["Debug.bStrictMutation"] = false;
	config["Debug.bSkipDisasmValidation"] = false;
}

bool SaveConfig() {
	if (!Data.ConfigPath[0]) return false;
	if (Data.ConfigPath[0] == ' ') {
		LOG(Info, MODULE_YAP, "No project file is selected.\n");
		return true;
	}

	// Check file ending
	char* ending = &Data.ConfigPath[lstrlenA(Data.ConfigPath) - 7];
	if ((lstrlenA(Data.ConfigPath) < 7 || lstrcmpA(ending, ".yaproj")) && lstrlenA(Data.ConfigPath) < sizeof(Data.ConfigPath) - 8) {
		memcpy(ending + 7, ".yaproj", 8);
	}

	// Open file
	HANDLE hFile = CreateFileA(Data.ConfigPath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
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
	void* pData;
	for (auto item : config) {
		// Write name
		WriteFile(hFile, item.first.data(), item.first.length() + 1, NULL, NULL);

		// Write data
		#define WRITE_CONFIG(primitive, id) else if ((pData = std::get_if<primitive>(&config[item.first]))) { WriteFile(hFile, &id, 1, NULL, NULL); WriteFile(hFile, pData, sizeof(primitive), NULL, NULL); }
		if ((pData = std::get_if<Buffer>(&config[item.first]))) {
			WriteFile(hFile, &ConfigTypes::Buffer, 1, NULL, NULL);
			size_t sz = reinterpret_cast<Buffer*>(pData)->Size();
			WriteFile(hFile, &sz, sizeof(sz), NULL, NULL);
			WriteFile(hFile, reinterpret_cast<Buffer*>(pData)->Data(), sz, NULL, NULL);
		}
		WRITE_CONFIG(bool, ConfigTypes::Bool)
		WRITE_CONFIG(int, ConfigTypes::Int)
		WRITE_CONFIG(uint64_t, ConfigTypes::UInt64)
		#undef WRITE_CONFIG
	}
	
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Saved project to %s\n", Data.ConfigPath);
	return true;
}

bool LoadConfig() {
	LoadDefaultConfig();
	char sig[3] = { 0 };
	DWORD ver = 0;

	// Open file
	HANDLE hFile = CreateFileA(Data.ConfigPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to load project", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Failed to load project: %d\n", GetLastError());
		Data.ConfigPath[0] = 0;
		return false;
	}

	// Read signature
	ReadFile(hFile, sig, 3, NULL, NULL);
	if (memcmp(sig, "YAP", 3)) {
		Modal("Invalid/corrupt project", "Error", MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Invalid/corrupt project\n");
		CloseHandle(hFile);
		Data.ConfigPath[0] = 0;
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
		Data.ConfigPath[0] = 0;
		return false;
	}

	// Read data
	// TODO
	
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Loaded %s\n", Data.ConfigPath);
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