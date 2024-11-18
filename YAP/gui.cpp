#include "gui.hpp"
#include "font.h"
#include "icons.h"
#include <d3d11.h>
#include <dxgi.h>
#include <stdlib.h>
#include <ctime>
#include <Psapi.h>
#include <Shlwapi.h>
#include "imgui_internal.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"
#include "util.h"
#include "asm.hpp"

static ID3D11Device* g_pd3dDevice = nullptr;
static ID3D11DeviceContext* g_pd3dDeviceContext = nullptr;
static IDXGISwapChain* g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
IDXGIOutput* g_pOutput = NULL;
bool bMinimized = false, bOpen = true, bInitialized = false;
const int width = 850;
const int height = 560;
ImGuiWindow* pWindow = NULL;
extern Asm* pAssembly;
ImWchar range[] = { 0xE005, 0xF8FF, 0 };

LRESULT WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI WindowThread(void* args);
void CleanupRenderTarget();
void CreateRenderTarget();
void CleanupDeviceD3D();
bool CreateDeviceD3D(HWND hWnd);
void EndGUI();
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

void InitGUI() {
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags = ImGuiConfigFlags_NavEnableKeyboard;
	io.IniFilename = NULL;
	ApplyImGuiTheme();
	io.Fonts->Clear();
	io.FontDefault = NULL;
	io.Fonts->AddFontFromMemoryCompressedTTF(font_compressed_data, font_compressed_size, 16.f);
	ImFontConfig config;
	config.MergeMode = true;
	config.GlyphMinAdvanceX = 16.f;
	io.Fonts->AddFontFromMemoryCompressedTTF(icons_compressed_data, icons_compressed_size, 16.f, &config, range);
	io.Fonts->Build();
}

// Opens file dialogue
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo) {
	// Initialize struct
	OPENFILENAME FileName = { 0 };
	FileName.lStructSize = sizeof(OPENFILENAME);
	FileName.hwndOwner = Data.hWnd;
	FileName.lpstrFilter = pFilter;
	FileName.nFilterIndex = 1;
	FileName.lpstrFile = pOut;
	FileName.nMaxFile = szOut;
	FileName.Flags = OFN_EXPLORER;
	if (!bSaveTo)
		FileName.Flags |= OFN_FILEMUSTEXIST;

	// Open dialogue
	bool bRet = false;
	if (bSaveTo) {
		bRet = GetSaveFileName(&FileName);
	} else {
		bRet = GetOpenFileName(&FileName);
	}

	// Return
	if (pFileNameOffset && bRet) {
		*pFileNameOffset = FileName.nFileOffset;
	}
	return bRet;
}

void SaveSettings() {
	// Get file
	char path[MAX_PATH];
	DWORD sz = MAX_PATH;
	if (!QueryFullProcessImageNameA(GetCurrentProcess(), 0, path, &sz)) {
		LOG(Failed, MODULE_YAP, "Failed to save settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	if (!PathRemoveFileSpecA(path) || lstrlenA(path) > MAX_PATH - 12) {
		LOG(Failed, MODULE_YAP, "Failed to save settings (misc)\n");
		return;
	}
	memcpy(&path[lstrlenA(path)], "\\yap.config", 12);

	// Write settings
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
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
		LOG(Failed, MODULE_YAP, "Failed to load settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	if (!PathRemoveFileSpecA(path) || lstrlenA(path) > MAX_PATH - 12) {
		LOG(Failed, MODULE_YAP, "Failed to load settings (misc)\n");
		return;
	}
	memcpy(&path[lstrlenA(path)], "\\yap.config", 12);

	// Read settings
	HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		LOG(Failed, MODULE_YAP, "Failed to load settings: %d (%s)\n", GetLastError(), path);
		return;
	}
	ReadFile(hFile, &Settings, sizeof(Settings_t), NULL, NULL);
	CloseHandle(hFile);
}

bool SaveProject() {
	// Check file ending
	char* ending = &Data.Project[lstrlenA(Data.Project) - 7];
	if ((lstrlenA(Data.Project) < 7 || lstrcmpA(ending, ".yaproj")) && lstrlenA(Data.Project) < sizeof(Data.Project) - 8) {
		memcpy(ending + 7, ".yaproj", 8);
	}

	// Open file
	HANDLE hFile = CreateFileA(Data.Project, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		if (Data.hWnd) MessageBoxA(Data.hWnd, "Failed to save project!", NULL, MB_OK | MB_ICONERROR);
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
		WriteFile(hFile, &Options.VM.VMFuncs.At(i), sizeof(ToVirt_t), NULL, NULL);
	}
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
		if (Data.hWnd) MessageBoxA(Data.hWnd, "Failed to load project!", NULL, MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Failed to load project: %d\n", GetLastError());
		Data.Project[0] = 0;
		return false;
	}

	// Read signature
	ReadFile(hFile, sig, 3, NULL, NULL);
	if (memcmp(sig, "YAP", 3)) {
		if (Data.hWnd) MessageBoxA(Data.hWnd, "Invalid/corrupt project!", NULL, MB_OK | MB_ICONERROR);
		LOG(Failed, MODULE_YAP, "Invalid/corrupt project\n");
		CloseHandle(hFile);
		Data.Project[0] = 0;
		return false;
	}

	// Read version
	ReadFile(hFile, &ver, sizeof(DWORD), NULL, NULL);
	if ((ver & ~__YAP_VERSION_MASK_PATCH__) != (__YAP_VERSION_NUM__ & ~__YAP_VERSION_MASK_PATCH__)) {
		if (Data.hWnd) MessageBoxA(Data.hWnd, "Version mismatch!", NULL, MB_OK | MB_ICONERROR);
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

void DrawGUI() {
	// End if window is closed
	if (!bOpen) {
		EndGUI();
		_exit(0);
	}
	
	ImGui::Begin("YAP", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_MenuBar);

	// Menu bar
	if (ImGui::BeginMenuBar()) {
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem(ICON_FILE " New", "Ctrl + N")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			if (ImGui::MenuItem(ICON_FOLDER_OPEN " Open", "Ctrl + O")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false); LoadProject(); }
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save", "Ctrl + S")) { SaveProject(); }
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save As", "Ctrl + Shift + S")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Settings")) {
			if (ImGui::MenuItem("Auto Update", NULL, &Settings.bCheckForUpdates)) { SaveSettings(); }
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("About")) {
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_QUESTION " Usage")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/Usage.md", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_QUESTION " Best Practices")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/Usage.md#best-practices", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/LICENSE", NULL, NULL, 0); }
			ImGui::EndMenu();
		}
		ImGui::EndMenuBar();
	}
	
	// Select file menu
	if (!Data.Project[0]) {
		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Create or select a project file").x) / 2, (ImGui::GetWindowSize().y - ImGui::GetTextLineHeight()) / 2));
		ImGui::Text("Create or select a project file");
	}

	// Configuration menu
	else if (!Data.bRunning) {
		ImGui::BeginTabBar("#Tabs");

		if (ImGui::BeginTabItem(ICON_BOX_ARCHIVE " Packing")) {
			IMGUI_TOGGLE("Enable Packer", Options.Packing.bEnabled);
			ImGui::SetItemTooltip("Wraps the original binary with a custom loader.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Don't Pack Resources", Options.Packing.bDontCompressRsrc);
			ImGui::SetItemTooltip("Preserves everything in the resource directory, keeping details such as icons and privileges.");
			ImGui::SliderInt("Depth", &Options.Packing.EncodingCounts, 1, 10);
			ImGui::SetItemTooltip("Number of times the application should be packed.\n1: packed app\n2: packed packed app\n3: packed packed packed app\netc.");
			ImGui::SliderInt("Compression Level", &Options.Packing.CompressionLevel, 1, 9);
			ImGui::SetItemTooltip("How compressed the binary should be.");
			ImGui::SliderInt("Mutation Level", &Options.Packing.MutationLevel, 1, 5);
			ImGui::SetItemTooltip("The amount of garbage that should be generated (more -> slower).");
			IMGUI_TOGGLE("Hide IAT", Options.Packing.bHideIAT);
			ImGui::SetItemTooltip("Attempts to hide the packed binaries IAT.");
			IMGUI_TOGGLE("Delayed Entry Point", Options.Packing.bDelayedEntry);
			ImGui::SetItemTooltip("Changes the entry point of the application during runtime.");
			IMGUI_TOGGLE("DLL Sideloading Mitigations", Options.Packing.bMitigateSideloading);
			ImGui::SetItemTooltip("Prioritizes DLLs in Windows directories, loading those first instead of DLLs placed in the local directory.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Only Load Microsoft Signed DLLs", Options.Packing.bOnlyLoadMicrosoft);
			ImGui::SetItemTooltip("Only allows DLLs that have been signed by Microsoft to be loaded.");
			IMGUI_TOGGLE("Direct Syscalls", Options.Packing.bDirectSyscalls);
			ImGui::SetItemTooltip("Skips use of some windows API functions and instead makes calls directly to the kernel, can break with future Windows updates.");
			IMGUI_TOGGLE("Anti-Dump", Options.Packing.bAntiDump);
			ImGui::SetItemTooltip("Prevent PE dumpers and reconstructors from dumping the running process.");
			IMGUI_TOGGLE("Anti-Debug", Options.Packing.bAntiDebug);
			ImGui::SetItemTooltip("Prevent debuggers from attaching to process.");
			IMGUI_TOGGLE("Anti-VM", Options.Packing.bAntiVM);
			ImGui::SetItemTooltip("Prevent app from running in a virtual machine.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Allow Hyper-V", Options.Packing.bAllowHyperV);
			ImGui::SetItemTooltip("Still run if the detected VM is only MS Hyper-V.");
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-Sandbox", Options.Packing.bAntiSandbox));
			DEBUG_ONLY(ImGui::SetItemTooltip("Prevent app from running in a sandboxed environment."));
			if (Options.Packing.bDelayedEntry && Options.Packing.Immitate == ExeStealth) Options.Packing.Immitate = YAP;
			if (!Options.Reassembly.bEnabled) ImGui::BeginDisabled();
			IMGUI_TOGGLE("Partial Unpacking", Options.Packing.bPartialUnpacking);
			ImGui::SetItemTooltip(Options.Reassembly.bEnabled ? "Only allows one function to be loaded at a time, preventing the whole program from being dumped at once." : "Requires reassembler to be enabled");
			ImGui::SameLine();
			ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
			ImGui::SetItemTooltip("This feature is not threadsafe, and only works on single threaded apps.");
			if (!Options.Reassembly.bEnabled) ImGui::EndDisabled();
			ImGui::Combo("Immitate Packer", (int*)&Options.Packing.Immitate, Options.Packing.bDelayedEntry ? "None\0Themida\0WinLicense\0UPX\0MPRESS\0Enigma\0" : "None\0Themida\0WinLicense\0UPX\0MPRESS\0Enigma\0ExeStealth\0");
			ImGui::SetItemTooltip("Changes some details about the packed binary to make it look like another packer.");
			IMGUI_TOGGLE("Enable Process Masquerading", Options.Packing.bEnableMasquerade);
			ImGui::SetItemTooltip("Makes the packed executable appear as a different process (NOT process hollowing).\nPlease note that the smaller the path the easier it is to use.");
			ImGui::SameLine();
			ImGui::InputText(" ", Options.Packing.Masquerade, MAX_PATH);
			IMGUI_TOGGLE("Mark Critical (Requires Admin)", Options.Packing.bMarkCritical);
			ImGui::SetItemTooltip("Marks the process as critical, causing the system to bluescreen when the process exits or is killed.\nRequires the packed process to be run with administrator privileges.");
			ImGui::InputText("Leave a Message", Options.Packing.Message, 64);
			ImGui::SetItemTooltip("Leave a little message for any possible reverse engineers.");
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem(ICON_CODE " Reassembler")) {
			ImGui::Text("The reassembler is currently expiremental, the only tested/supported compilers are MSVC and GCC/G++.");
			IMGUI_TOGGLE("Enabled", Options.Reassembly.bEnabled);
			ImGui::SetItemTooltip("Disassembles your application, modifies the assembly a ton, and then assembles the modified assembly.");
			IMGUI_TOGGLE("Strip Debug Symbols", Options.Reassembly.bStrip);
			ImGui::SetItemTooltip("Remove debugging information from the PE.");
			IMGUI_TOGGLE("Strip DOS Stub", Options.Reassembly.bStripDOSStub);
			ImGui::SetItemTooltip("Remove DOS stub from the PE.");
			IMGUI_TOGGLE("Instruction Substitution", Options.Reassembly.bSubstitution);
			ImGui::SetItemTooltip("Replaces some existing instructions with other, more complicated alternatives.\n");
			ImGui::InputScalar("Rebase Image", ImGuiDataType_U64, &Options.Reassembly.Rebase, NULL, NULL, "%p", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::SetItemTooltip("Changes images prefered base address. (0 to disable)");
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem(ICON_MICROCHIP " VM")) {
			if (!Options.Packing.bEnabled || !Options.Reassembly.bEnabled) {
				ImGui::BeginDisabled();
				bool bDisabled = false;
				ImGui::Checkbox("Enable VM", &bDisabled);
			} else {
				IMGUI_TOGGLE("Enable VM", Options.VM.bEnabled);
			}
			ImGui::SetItemTooltip("Enables virtualization functionality, requires packer & reassembler to be enabled.");
			if (ImGui::Button("Add Function (Max 256)")) {
				if (Options.VM.VMFuncs.Size() >= 256) {
					MessageBoxA(Data.hWnd, "Maximum number of functions selected!", NULL, MB_ICONINFORMATION | MB_OK);
				} else {
					ToVirt_t empty;
					Options.VM.VMFuncs.Push(empty);
				}
			}

			for (int i = 0, n = Options.VM.VMFuncs.Size(); i < n; i++) {
				// Label
				char buf[512];

				// Dropdown
				wsprintfA(buf, "BtnFn%d", i);
				ImGui::PushID(buf);
				wsprintfA(buf, "Function %d", i + 1);
				char name[sizeof(Options.VM.VMFuncs.At(i).Name)] = { 0 };
				memcpy(name, Options.VM.VMFuncs.At(i).Name, sizeof(name));
				if (ImGui::InputText(buf, name, sizeof(name))) {
					ToVirt_t entry = Options.VM.VMFuncs.At(i);
					memcpy(entry.Name, name, sizeof(name));
					Options.VM.VMFuncs.Replace(i, entry);
				}
				ImGui::PopID();
				ImGui::SetItemTooltip("Name of exported function");
				ImGui::SameLine();
				wsprintfA(buf, "BtnCheck%d", i);
				ImGui::PushID(buf);
				bool bSet = Options.VM.VMFuncs.At(i).bRemoveExport;
				if (ImGui::Checkbox("Remove Export", &bSet)) {
					ToVirt_t entry = Options.VM.VMFuncs.At(i);
					entry.bRemoveExport = bSet;
					Options.VM.VMFuncs.Replace(i, entry);
				}
				ImGui::PopID();
				ImGui::SetItemTooltip("Remove function from export table");

				// Remove button
				ImGui::SameLine();
				wsprintfA(buf, "BtnRemove%d", i);
				ImGui::PushID(buf);
				if (ImGui::Button("Remove")) {
					uint64_t holder = 0;
					Options.VM.VMFuncs.Remove(i);
					n--;
					i--;
				}
				ImGui::PopID();
			}
			if (!Options.Packing.bEnabled || !Options.Reassembly.bEnabled) ImGui::EndDisabled();
			ImGui::EndTabItem();
		}

#ifdef _DEBUG
		if (ImGui::BeginTabItem(ICON_BUG " Debug")) {
			IMGUI_TOGGLE("Dump Disassembly", Options.Debug.bDumpAsm);
			IMGUI_TOGGLE("Dump Individual Sections", Options.Debug.bDumpSections);
			IMGUI_TOGGLE("Dump Function Ranges", Options.Debug.bDumpFunctions);
			IMGUI_TOGGLE("Create Breakpoints", Options.Debug.bGenerateBreakpoints);
			IMGUI_TOGGLE("Wrap Real Instructions in NOPs", Options.Debug.bGenerateMarks);
			IMGUI_TOGGLE("Disable Mutation", Options.Debug.bDisableMutations);
			IMGUI_TOGGLE("Disable Relocations", Options.Debug.bDisableRelocations);
			if (ImGui::TreeNode("Icon Tests")) {
				ImGui::DebugTextEncoding(ICON_FILE_SHIELD ICON_SHIELD ICON_SHIELD_HALVED ICON_TRIANGLE_EXCLAMATION ICON_CIRCLE_INFO ICON_CIRCLE_QUESTION ICON_FOLDER_OPEN ICON_FILE ICON_FLOPPY_DISK ICON_CODE ICON_MICROCHIP ICON_BOX ICON_BOX_OPEN ICON_BOX_ARCHIVE);
				ImGui::TreePop();
			}
			ImGui::ShowMetricsWindow();
			ImGui::EndTabItem();
		}
#endif

		if (ImGui::BeginTabItem(ICON_GEARS " Advanced")) {
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem(ICON_CIRCLE_INFO " Version")) {
			ImGui::Text("YAP Version: " __YAP_VERSION__);
			ImGui::Text("ImGui Version: " IMGUI_VERSION);
			ImGui::Text("Zydis Version: %d.%d.%d", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
			ImGui::Text("AsmJit Version: %d.%d.%d", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
			ImGui::Text("Build: " __YAP_BUILD__);
			ImGui::Text("Build Time: " __DATE__ " " __TIME__);
			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
		ImGui::SetCursorPos(ImVec2(770 - (ImGui::GetScrollMaxY() > 0.f ? ImGui::GetWindowScrollbarRect(ImGui::GetCurrentWindow(), ImGuiAxis_Y).GetWidth() : 0), 530 + ImGui::GetScrollY()));
		if (ImGui::Button(ICON_SHIELD_HALVED " Protect")) {
			char file[MAX_PATH] = { 0 };
			if (!OpenFileDialogue(file, MAX_PATH, "Binaries\0*.exe;*.dll;*.sys\0All Files\0*.*\0", NULL, false)) {
				MessageBoxA(Data.hWnd, "Fatal!", NULL, MB_OK | MB_ICONERROR);
				LOG(Failed, MODULE_YAP, "Failed to open file dialogue: %d\n", CommDlgExtendedError());
			} else {
				pAssembly = new Asm(file);
				CreateThread(0, 0, Begin, 0, 0, 0);
			}
		}
	}

	// Data
	else {
		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Doing Magical Things...").x) / 2, (ImGui::GetWindowSize().y - ImGui::GetTextLineHeight()) / 2));
		ImGui::Text("Doing Magical Things...");
	}

	ImGui::End();

	// Save file dialogue
	if (Data.bWaitingOnFile && !Data.bUserCancelled) {
		while (!OpenFileDialogue(Data.SaveFileName, MAX_PATH, "Binaries\0*.exe;*.dll;*.sys\0All Files\0*.*\0", NULL, true)) {
			if (MessageBoxA(Data.hWnd, "Failed to get save file name!", NULL, MB_ICONERROR | MB_RETRYCANCEL) == IDCANCEL) {
				Data.bUserCancelled = true;
				break;
			}
		}
		Data.bWaitingOnFile = false;
	}
	if (!pWindow) pWindow = ImGui::FindWindowByName("YAP");
}

bool BeginGUI() {
	if (bInitialized)
		return false;
	bInitialized = true;

	// Register class
	WNDCLASSEXA WindowClass = { 0 };
	WindowClass.cbSize = sizeof(WNDCLASSEXA);
	WindowClass.lpfnWndProc = (WNDPROC)WndProc;
	WindowClass.hInstance = GetModuleHandle(NULL);
	WindowClass.style = CS_CLASSDC;
	WindowClass.lpszClassName = "YAP";
	if (!RegisterClassExA(&WindowClass)) {
		return (bInitialized = false);
	}

	// Create window
	if (!(Data.hWnd = CreateWindowExA(
		0,
		"YAP",
		"YAP",
		0,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		width,
		height,
		NULL,
		NULL,
		GetModuleHandleA(NULL),
		NULL
	))) {
		UnregisterClassA("YAP", GetModuleHandleA(NULL));
		return (bInitialized = false);
	}
	SetWindowLongA(Data.hWnd, GWL_STYLE, 0);
	ShowWindow(Data.hWnd, SW_SHOW);

	// Setup ImGui
	CreateDeviceD3D(Data.hWnd);
	ImGui_ImplWin32_Init(Data.hWnd);
	ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
	CleanupRenderTarget();
	g_pSwapChain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
	g_pSwapChain->GetContainingOutput(&g_pOutput);
	CreateRenderTarget();

	// Create rendering thread
	if (!CreateThread(0, 0, WindowThread, 0, 0, 0)) {
		EndGUI();
		UnregisterClassA("YAP", GetModuleHandleA(NULL));
		return false;
	}

	// Handle message queue
	MSG msg;
	while (bInitialized) {
		while (bInitialized && PeekMessage(&msg, Data.hWnd, 0, 0, 1)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		if (!ImGui::IsMouseDown(0)) {
			g_pOutput->WaitForVBlank();
		}
	}
	return true;
}

void MoveWindow(int x, int y, bool bRelative) {
	if (bRelative) {
		RECT WindowRect;
		GetWindowRect(Data.hWnd, &WindowRect);
		x += WindowRect.left;
		y += WindowRect.top;
	}
	SetWindowPos(Data.hWnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void EndGUI() {
	if (!bInitialized)
		return;
	bInitialized = false;
	pWindow = (ImGuiWindow*)1;
	ImGui_ImplDX11_Shutdown();
	ImGui_ImplWin32_Shutdown();
	CleanupDeviceD3D();
}

// Window thread
DWORD WINAPI WindowThread(void* args) {
	while (bInitialized) {
		// Setup frame
		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		if (pWindow) {
			// Minimize window
			if (pWindow->Collapsed) {
				if (!bMinimized) {
					ShowWindow(Data.hWnd, SW_MINIMIZE);
				}
				ImGui::SetWindowCollapsed(pWindow, false);
			}

			// Move window
			if (pWindow->Pos.x != 0 || pWindow->Pos.y != 0) {
				MoveWindow((int)pWindow->Pos.x, (int)pWindow->Pos.y, true);
			}
		}

		// Render
		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(width, height));
		DrawGUI();

		// Finish frame
		ImGui::Render();
		g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		g_pSwapChain->Present(1, 0);
	}
	EndGUI();
	return 0;
}

// Message handler
LRESULT WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_QUIT:
	case WM_DESTROY:
	case WM_CLOSE:
		EndGUI();
		break;
	case WM_SHOWWINDOW:
		bMinimized = wParam == FALSE;
		break;
	case WM_KEYDOWN:
		if (!(lParam & KF_REPEAT) && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) {
			switch (wParam) {
			case 0x53: // S
				if (GetAsyncKeyState(VK_SHIFT) & 0x8000) {
					OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
					SaveProject();
				} else {
					SaveProject();
				}
				break;
			case 0x4E: // N
				OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
				SaveProject();
				break;
			case 0x4F: // O
				OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false);
				LoadProject();
			}
		}
	}
	return ImGui_ImplWin32_WndProcHandler(hWnd, uMsg, wParam, lParam) ? TRUE : DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void ApplyImGuiTheme() {
	ImGuiStyle& style = ImGui::GetStyle();

	style.Alpha = 1.0f;
	style.DisabledAlpha = 0.6000000238418579f;
	style.WindowPadding = ImVec2(8.0f, 8.0f);
	style.WindowRounding = 0.0f;
	style.WindowBorderSize = 1.0f;
	style.WindowMinSize = ImVec2(32.0f, 32.0f);
	style.WindowTitleAlign = ImVec2(0.0f, 0.5f);
	style.WindowMenuButtonPosition = ImGuiDir_Right;
	style.ChildRounding = 0.0f;
	style.ChildBorderSize = 1.0f;
	style.PopupRounding = 0.0f;
	style.PopupBorderSize = 1.0f;
	style.FramePadding = ImVec2(4.0f, 3.0f);
	style.FrameRounding = 5.0f;
	style.FrameBorderSize = 0.0f;
	style.ItemSpacing = ImVec2(8.0f, 4.0f);
	style.ItemInnerSpacing = ImVec2(4.0f, 4.0f);
	style.CellPadding = ImVec2(4.0f, 2.0f);
	style.IndentSpacing = 21.0f;
	style.ColumnsMinSpacing = 6.0f;
	style.ScrollbarSize = 14.0f;
	style.ScrollbarRounding = 9.0f;
	style.GrabMinSize = 10.0f;
	style.GrabRounding = 5.0f;
	style.TabRounding = 4.0f;
	style.TabBorderSize = 0.0f;
	style.TabMinWidthForCloseButton = 0.0f;
	style.ColorButtonPosition = ImGuiDir_Right;
	style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
	style.SelectableTextAlign = ImVec2(0.0f, 0.0f);

	style.Colors[ImGuiCol_Text] = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
	style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.4980392158031464f, 0.4980392158031464f, 0.4980392158031464f, 1.0f);
	style.Colors[ImGuiCol_WindowBg] = ImVec4(0.09871244430541992f, 0.09871145337820053f, 0.09871145337820053f, 1.0f);
	style.Colors[ImGuiCol_ChildBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_PopupBg] = ImVec4(0.0784313753247261f, 0.0784313753247261f, 0.0784313753247261f, 0.9399999976158142f);
	style.Colors[ImGuiCol_Border] = ImVec4(0.4274509847164154f, 0.4274509847164154f, 0.4980392158031464f, 0.5f);
	style.Colors[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_FrameBg] = ImVec4(0.1587982773780823f, 0.1587966829538345f, 0.1587966829538345f, 1.0f);
	style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.2360491305589676f, 0.2360502332448959f, 0.2360514998435974f, 1.0f);
	style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.3133015930652618f, 0.313303142786026f, 0.3133047223091125f, 1.0f);
	style.Colors[ImGuiCol_TitleBg] = ImVec4(0.09803921729326248f, 0.09803921729326248f, 0.09803921729326248f, 1.0f);
	style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.09803921729326248f, 0.09803921729326248f, 0.09803921729326248f, 1.0f);
	style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.0f, 0.0f, 0.0f, 0.5099999904632568f);
	style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.1372549086809158f, 0.1372549086809158f, 0.1372549086809158f, 1.0f);
	style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.01960784383118153f, 0.01960784383118153f, 0.01960784383118153f, 0.5299999713897705f);
	style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.3098039329051971f, 0.3098039329051971f, 0.3098039329051971f, 1.0f);
	style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.407843142747879f, 0.407843142747879f, 0.407843142747879f, 1.0f);
	style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.5098039507865906f, 0.5098039507865906f, 0.5098039507865906f, 1.0f);
	style.Colors[ImGuiCol_CheckMark] = ImVec4(0.3921568691730499f, 0.3921568691730499f, 0.3921568691730499f, 1.0f);
	style.Colors[ImGuiCol_SliderGrab] = ImVec4(0.3133047223091125f, 0.3133015930652618f, 0.3133015930652618f, 1.0f);
	style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(0.3905579447746277f, 0.3905540406703949f, 0.3905540406703949f, 1.0f);
	style.Colors[ImGuiCol_Button] = ImVec4(0.1568627506494522f, 0.1568627506494522f, 0.1568627506494522f, 1.0f);
	style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.2352941185235977f, 0.2352941185235977f, 0.2352941185235977f, 1.0f);
	style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.3137255012989044f, 0.3137255012989044f, 0.3137255012989044f, 1.0f);
	style.Colors[ImGuiCol_Header] = ImVec4(0.1568627506494522f, 0.1568627506494522f, 0.1568627506494522f, 1.0f);
	style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.2352941185235977f, 0.2352941185235977f, 0.2352941185235977f, 1.0f);
	style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.3137255012989044f, 0.3137255012989044f, 0.3137255012989044f, 1.0f);
	style.Colors[ImGuiCol_Separator] = ImVec4(0.1568627506494522f, 0.1568627506494522f, 0.1568627506494522f, 1.0f);
	style.Colors[ImGuiCol_SeparatorHovered] = ImVec4(0.2352941185235977f, 0.2352941185235977f, 0.2352941185235977f, 1.0f);
	style.Colors[ImGuiCol_SeparatorActive] = ImVec4(0.3137255012989044f, 0.3137255012989044f, 0.3137255012989044f, 1.0f);
	style.Colors[ImGuiCol_ResizeGrip] = ImVec4(0.1568627506494522f, 0.1568627506494522f, 0.1568627506494522f, 1.0f);
	style.Colors[ImGuiCol_ResizeGripHovered] = ImVec4(0.2352941185235977f, 0.2352941185235977f, 0.2352941185235977f, 1.0f);
	style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(0.3137255012989044f, 0.3137255012989044f, 0.3137255012989044f, 1.0f);
	style.Colors[ImGuiCol_Tab] = ImVec4(0.1568627506494522f, 0.1568627506494522f, 0.1568627506494522f, 1.0f);
	style.Colors[ImGuiCol_TabHovered] = ImVec4(0.2352941185235977f, 0.2352941185235977f, 0.2352941185235977f, 1.0f);
	style.Colors[ImGuiCol_TabActive] = ImVec4(0.3137255012989044f, 0.3137255012989044f, 0.3137255012989044f, 1.0f);
	style.Colors[ImGuiCol_TabUnfocused] = ImVec4(0.06666667014360428f, 0.1019607856869698f, 0.1450980454683304f, 1.0f);
	style.Colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.1333333402872086f, 0.2588235437870026f, 0.4235294163227081f, 1.0f);
	style.Colors[ImGuiCol_PlotLines] = ImVec4(0.6078431606292725f, 0.6078431606292725f, 0.6078431606292725f, 1.0f);
	style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(1.0f, 0.4274509847164154f, 0.3490196168422699f, 1.0f);
	style.Colors[ImGuiCol_PlotHistogram] = ImVec4(0.8980392217636108f, 0.6980392336845398f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(1.0f, 0.6000000238418579f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_TableHeaderBg] = ImVec4(0.1882352977991104f, 0.1882352977991104f, 0.2000000029802322f, 1.0f);
	style.Colors[ImGuiCol_TableBorderStrong] = ImVec4(0.3098039329051971f, 0.3098039329051971f, 0.3490196168422699f, 1.0f);
	style.Colors[ImGuiCol_TableBorderLight] = ImVec4(0.2274509817361832f, 0.2274509817361832f, 0.2470588237047195f, 1.0f);
	style.Colors[ImGuiCol_TableRowBg] = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
	style.Colors[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.05999999865889549f);
	style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_DragDropTarget] = ImVec4(1.0f, 1.0f, 0.0f, 0.8999999761581421f);
	style.Colors[ImGuiCol_NavHighlight] = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.0f, 1.0f, 1.0f, 0.699999988079071f);
	style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.800000011920929f, 0.800000011920929f, 0.800000011920929f, 0.2000000029802322f);
	style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.800000011920929f, 0.800000011920929f, 0.800000011920929f, 0.3499999940395355f);
}


/***** IMGUI PROVIDED DX11 FUNCTIONS *****/

bool CreateDeviceD3D(HWND hWnd)
{
	// Setup swap chain
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hWnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
		res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
	if (res != S_OK)
		return false;

	CreateRenderTarget();
	return true;
}

void CleanupDeviceD3D()
{
	CleanupRenderTarget();
	if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
	if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
	if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget()
{
	ID3D11Texture2D* pBackBuffer;
	g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
	pBackBuffer->Release();
}

void CleanupRenderTarget()
{
	if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}