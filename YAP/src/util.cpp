#include "util.hpp"



void SaveSettings() {
	// Get file
	char path[MAX_PATH];
	DWORD sz = MAX_PATH;
	if (!QueryFullProcessImageNameA(GetCurrentProcess(), 0, path, &sz)) {
		Modal("Failed to save settings");
		LOG(Failed, MODULE_YAP, "Failed to save settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	if (!PathRemoveFileSpecA(path) || lstrlenA(path) > MAX_PATH - 12) {
		Modal("Failed to save settings");
		LOG(Failed, MODULE_YAP, "Failed to save settings (misc)\n");
		return;
	}
	memcpy(&path[lstrlenA(path)], "\\yap.config", 12);

	// Write settings
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to save settings");
		LOG(Failed, MODULE_YAP, "Failed to save settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	WriteFile(hFile, &Settings, sizeof(Settings_t), NULL, NULL);
	CloseHandle(hFile);
}

void LoadSettings() {
	// Get file
	char path[MAX_PATH];
	DWORD sz = MAX_PATH;
	if (!QueryFullProcessImageNameA(GetCurrentProcess(), 0, path, &sz)) {
		Modal("Failed to load settings");
		LOG(Failed, MODULE_YAP, "Failed to load settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	if (!PathRemoveFileSpecA(path) || lstrlenA(path) > MAX_PATH - 12) {
		Modal("Failed to load settings");
		LOG(Failed, MODULE_YAP, "Failed to load settings (misc)\n");
		return;
	}
	memcpy(&path[lstrlenA(path)], "\\yap.config", 12);

	// Read settings
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to load settings");
		LOG(Failed, MODULE_YAP, "Failed to load settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	ReadFile(hFile, &Settings, sizeof(Settings_t), NULL, NULL);
	CloseHandle(hFile);
}

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
		Modal("Failed to save project");
		LOG(Failed, MODULE_YAP, "Failed to save project: %d\n", GetLastError());
		return false;
	}

	// Write sig + version
	WriteFile(hFile, "YAP", 3, NULL, NULL);
	DWORD ver = __YAP_VERSION_NUM__;
	WriteFile(hFile, &ver, sizeof(DWORD), NULL, NULL);

	// Write data
	BYTE* pTemp = Options.VM.VMFuncs.raw.pBytes;
	Options.VM.VMFuncs.raw.pBytes = NULL;
	WriteFile(hFile, &Options, sizeof(Options_t), NULL, NULL);
	Options.VM.VMFuncs.raw.pBytes = pTemp;

	// Write VM funcs
	for (int i = 0; i < Options.VM.VMFuncs.Size(); i++) {
		WriteFile(hFile, &Options.VM.VMFuncs[i], sizeof(ToVirt_t), NULL, NULL);
	}
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Saved project to %s\n", Data.Project);
	return true;
}

bool LoadProject() {
	char sig[3] = { 0 };
	DWORD ver = 0;
	Options.VM.VMFuncs.Release();

	// Open file
	HANDLE hFile = CreateFileA(Data.Project, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Modal("Failed to load project");
		LOG(Failed, MODULE_YAP, "Failed to load project: %d\n", GetLastError());
		Data.Project[0] = 0;
		return false;
	}

	// Read signature
	ReadFile(hFile, sig, 3, NULL, NULL);
	if (memcmp(sig, "YAP", 3)) {
		Modal("Invalid/corrupt project");
		LOG(Failed, MODULE_YAP, "Invalid/corrupt project\n");
		CloseHandle(hFile);
		Data.Project[0] = 0;
		return false;
	}

	// Read version
	ReadFile(hFile, &ver, sizeof(DWORD), NULL, NULL);
	if ((ver & ~__YAP_VERSION_MASK_PATCH__) != (__YAP_VERSION_NUM__ & ~__YAP_VERSION_MASK_PATCH__)) {
		Modal("Version mismatch");
		LOG(Failed, MODULE_YAP, "Version mismatch\n");
		LOG(Info_Extended, MODULE_YAP, "Current version: " __YAP_VERSION__ " " __YAP_BUILD__ "\n");
		LOG(Info_Extended, MODULE_YAP, "Project version: %d.%d.%d %s\n", ver & __YAP_VERSION_MASK_MAJOR__, ver & __YAP_VERSION_MASK_MINOR__, ver & __YAP_VERSION_MASK_PATCH__, (ver & __YAP_VERSION_MASK_DEBUG__) ? "DEBUG" : "RELEASE");
		CloseHandle(hFile);
		Data.Project[0] = 0;
		return false;
	}

	// Read data
	ReadFile(hFile, &Options, sizeof(Options_t), NULL, NULL);
	
	// Read VM funcs
	Options.VM.VMFuncs.raw.pBytes = reinterpret_cast<BYTE*>(malloc(Options.VM.VMFuncs.raw.u64Size));
	for (int i = 0; i < Options.VM.VMFuncs.Size(); i++) {
		ReadFile(hFile, Options.VM.VMFuncs.raw.pBytes + i * sizeof(ToVirt_t), sizeof(ToVirt_t), NULL, NULL);
	}
	CloseHandle(hFile);
	LOG(Success, MODULE_YAP, "Loaded %s\n", Data.Project);
	return true;
}

void Buffer::Merge(_In_ Buffer Other, _In_ bool bDontFree) {
    if (!Other.pBytes || !Other.u64Size) {
        return;
    } else if (!pBytes || !u64Size) {
        pBytes = Other.pBytes;
        u64Size = Other.u64Size;
    } else {
        Allocate(u64Size + Other.u64Size);
        if (!pBytes) {
            DebugBreak();
            exit(1);
        }
        memcpy(pBytes + u64Size - Other.u64Size, Other.pBytes, Other.u64Size);
        if (!bDontFree) {
            Other.Release();
        }
    }
}

void Buffer::Allocate(_In_ uint64_t Size) {
	if (!Size) {
		Release();
		return;
	}
	Data.Reserved += Size - u64Size;
	Data.InUse += Size - u64Size;
	u64Size = Size;
	pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, u64Size));
}

void Buffer::Release() {
    if (pBytes) {
		free(pBytes);
		Data.Reserved -= u64Size;
		Data.InUse -= u64Size;
	}
    pBytes = NULL;
    u64Size = 0;
}

uint64_t rand64() {
	uint64_t ret = rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	return ret;
}