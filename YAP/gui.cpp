#define GLFW_EXPOSE_NATIVE_WIN32
#include "gui.hpp"
#include "font.hpp"
#include "icons.hpp"
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include <stdlib.h>
#include <ctime>
#include <Psapi.h>
#include <Shlwapi.h>
#include <imgui_internal.h>
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "util.hpp"
#include "asm.hpp"

// Globals
bool bMinimized = false, bOpen = true, bInitialized = false;
const int width = 850;
const int height = 560;
ImGuiWindow* pImGuiWindow = NULL;
extern Asm* pAssembly;
ImWchar range[] = { 0xE005, 0xF8FF, 0 };
struct {
	char* pTitle = NULL;
	char* pText = NULL;
	UINT uType = 0;
} CurrentModal;

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

void DrawGUI() {
// Dont do anything if window is not shown
	if (!bOpen || bMinimized) return;
	
	ImGui::Begin("Yet Another Packer", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoTitleBar);

	// Menu bar
	if (ImGui::BeginMenuBar()) {
		//ImGui::Text("Yet Another Packer    |");
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem(ICON_FILE " New", "Ctrl + N")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			if (ImGui::MenuItem(ICON_FOLDER_OPEN " Open", "Ctrl + O")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false); LoadProject(); }
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save", "Ctrl + S")) { SaveProject(); }
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save As", "Ctrl + Shift + S") && Data.Project[0]) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("About")) {
			if (ImGui::MenuItem(ICON_CIRCLE_QUESTION " Feature Help")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/Features.md", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { Modal("MIT License\n\nCopyright (c) 2024-2025 undisassemble\nCopyright (c) 2014-2025 Omar Cornut\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.", ICON_CIRCLE_INFO " License", MB_OK); }
			ImGui::EndMenu();
		}
		ImGui::SetCursorPos(ImVec2((width - ImGui::CalcTextSize("Yet Another Packer").x) / 2, 0));
		ImGui::Text("Yet Another Packer");
		if (ImGui::CollapseButton(ImGui::GetCurrentWindow()->GetID("#COLLAPSE"), ImVec2(802, 3))) { ImGui::GetCurrentWindow()->Collapsed = !ImGui::GetCurrentWindow()->Collapsed; }
		if (ImGui::CloseButton(ImGui::GetCurrentWindow()->GetID("#CLOSE"), ImVec2(824, 3))) { bOpen = false; }
		ImGui::EndMenuBar();
	}
	
	// Select file menu
	if (!Data.Project[0]) {
		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Create or select a project file").x) / 2, (ImGui::GetWindowSize().y - ImGui::GetTextLineHeight()) / 2));
		ImGui::Text("Create or select a project file");
		ImGui::SetCursorPos(ImVec2((ImGui::GetWindowSize().x - ImGui::CalcTextSize("Continue without project >>>").x) / 2, (ImGui::GetWindowSize().y + ImGui::GetTextLineHeight()) / 2));
		if (ImGui::TextLink("Continue without project >>>")) {
			Data.Project[0] = ' ';
			Data.Project[1] = 0;
		}
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
			ImGui::SameLine();
			IMGUI_TOGGLE("API Emulation", Options.Packing.bAPIEmulation);
			ImGui::SetItemTooltip("Emulate some simple WINAPI functions.\n");
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
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-Patch", Options.Packing.bAntiPatch));
			DEBUG_ONLY(ImGui::SetItemTooltip("Verify signature of binary before loading.\n"));
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-VM", Options.Packing.bAntiVM));
			DEBUG_ONLY(ImGui::SetItemTooltip("Prevent app from running in a virtual machine."));
			DEBUG_ONLY(ImGui::SameLine());
			DEBUG_ONLY(IMGUI_TOGGLE("Allow Hyper-V", Options.Packing.bAllowHyperV));
			DEBUG_ONLY(ImGui::SetItemTooltip("Still run if the detected VM is only MS Hyper-V."));
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
				if (Options.VM.VMFuncs.Size() < 256) {
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
				char name[sizeof(Options.VM.VMFuncs[i].Name)] = { 0 };
				memcpy(name, Options.VM.VMFuncs[i].Name, sizeof(name));
				if (ImGui::InputText(buf, name, sizeof(name))) {
					ToVirt_t entry = Options.VM.VMFuncs[i];
					memcpy(entry.Name, name, sizeof(name));
					Options.VM.VMFuncs.Replace(i, entry);
				}
				ImGui::PopID();
				ImGui::SetItemTooltip("Name of exported function");
				ImGui::SameLine();
				wsprintfA(buf, "BtnCheck%d", i);
				ImGui::PushID(buf);
				bool bSet = Options.VM.VMFuncs[i].bRemoveExport;
				if (ImGui::Checkbox("Remove Export", &bSet)) {
					ToVirt_t entry = Options.VM.VMFuncs[i];
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

		if (ImGui::BeginTabItem(ICON_GEARS " Advanced")) {
			if (ImGui::TreeNode("Packer")) {
				BYTE MIN = 0;
				BYTE MAX = 9;
				ImGui::PushItemWidth(20);
				ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(2.f, 8.f));
				ImGui::PushID("UPXVersionMajor");
				ImGui::DragScalar(".", ImGuiDataType_U8, &Options.Advanced.UPXVersionMajor, 1.f, &MIN, &MAX);
				ImGui::PopID();
				ImGui::SameLine();
				ImGui::PushID("UPXVersionMinor");
				ImGui::DragScalar(".", ImGuiDataType_U8, &Options.Advanced.UPXVersionMinor, 1.f, &MIN, &MAX);
				ImGui::PopID();
				ImGui::SameLine();
				ImGui::DragScalar("UPX Version", ImGuiDataType_U8, &Options.Advanced.UPXVersionPatch, 1.f, &MIN, &MAX);
				ImGui::PopStyleVar();
				ImGui::PopItemWidth();
				IMGUI_TOGGLE("Fake Symbol Table", Options.Advanced.bFakeSymbols);
				IMGUI_TOGGLE("Mutate " ICON_TRIANGLE_EXCLAMATION, Options.Advanced.bMutateAssembly);
				IMGUI_TOGGLE("Semi-random Section Names", Options.Advanced.bSemiRandomSecNames);
				IMGUI_TOGGLE("Full-random Section Names", Options.Advanced.bTrueRandomSecNames);
				ImGui::InputText("Section 1 Name", Options.Advanced.Sec1Name, 9);
				ImGui::InputText("Section 2 Name", Options.Advanced.Sec2Name, 9);
				ImGui::TreePop();
			}
			if (ImGui::TreeNode("VM")) {
				IMGUI_TOGGLE("Delete Virtualized Functions", Options.Advanced.bDeleteVirtualizedFunctions);
				ImGui::TreePop();
			}
			ImGui::EndTabItem();
		}

#ifdef _DEBUG
		if (ImGui::BeginTabItem(ICON_BUG " Style Editor")) {
			ImGui::ShowStyleEditor();
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem(ICON_BUG " Debug")) {
			IMGUI_TOGGLE("Dump Disassembly", Options.Debug.bDumpAsm);
			IMGUI_TOGGLE("Dump Individual Sections", Options.Debug.bDumpSections);
			IMGUI_TOGGLE("Dump Function Ranges", Options.Debug.bDumpFunctions);
			IMGUI_TOGGLE("Create Breakpoints", Options.Debug.bGenerateBreakpoints);
			IMGUI_TOGGLE("Wrap Real Instructions in NOPs", Options.Debug.bGenerateMarks);
			IMGUI_TOGGLE("Strict Mutation", Options.Debug.bStrictMutation);
			IMGUI_TOGGLE("Disable Relocations", Options.Debug.bDisableRelocations);
			if (ImGui::TreeNode("Icon Tests")) {
				ImGui::DebugTextEncoding(ICON_FILE_SHIELD ICON_SHIELD ICON_SHIELD_HALVED ICON_TRIANGLE_EXCLAMATION ICON_CIRCLE_INFO ICON_CIRCLE_QUESTION ICON_FOLDER_OPEN ICON_FILE ICON_FLOPPY_DISK ICON_CODE ICON_MICROCHIP ICON_BOX ICON_BOX_OPEN ICON_BOX_ARCHIVE ICON_BUG);
				ImGui::TreePop();
			}
			ImGui::ShowMetricsWindow();
			ImGui::EndTabItem();
		}
#endif

		if (ImGui::BeginTabItem(ICON_CIRCLE_INFO " Version")) {
			ImGui::SeparatorText("Version information");
			ImGui::Text("YAP: " __YAP_VERSION__);
			ImGui::Text("ImGui: " IMGUI_VERSION);
			ImGui::Text("Zydis: %d.%d.%d", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
			ImGui::Text("AsmJit: %d.%d.%d", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
			ImGui::Text("GLFW: %s", glfwGetVersionString());
			ImGui::Text("OpenGL: %s", glGetString(GL_VERSION));
			ImGui::SeparatorText("Build information");
			ImGui::Text("Build: " __YAP_BUILD__);
			ImGui::Text("Time: " __DATE__ " @ " __TIME__);
			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
		ImGui::SetCursorPos(ImVec2(770 - (ImGui::GetScrollMaxY() > 0.f ? ImGui::GetCurrentWindow()->ScrollbarSizes[0] : 0), 530 + ImGui::GetScrollY()));
		if (ImGui::Button(ICON_SHIELD_HALVED " Protect")) {
			char file[MAX_PATH] = { 0 };
			if (!OpenFileDialogue(file, MAX_PATH, "Binaries\0*.exe;*.dll;*.sys\0All Files\0*.*\0", NULL, false)) {
				Modal("Failed to get file name");
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

	// Modals
	if (CurrentModal.pText) {
		ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), 0, ImVec2(0.5f, 0.5f));
		ImGui::OpenPopup(CurrentModal.pTitle);
		if (ImGui::BeginPopupModal(CurrentModal.pTitle, NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
			ImGui::Text(CurrentModal.pText);

			// Beautiful, isnt it?
			switch (CurrentModal.uType) {
			case MB_OKCANCEL:
				if (ImGui::Button("OK")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDOK;
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDCANCEL;
				}
				break;
			case MB_YESNO:
				if (ImGui::Button("Yes")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDYES;
				}
				ImGui::SameLine();
				if (ImGui::Button("No")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDNO;
				}
				break;
			case MB_YESNOCANCEL:
				if (ImGui::Button("Yes")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDYES;
				}
				ImGui::SameLine();
				if (ImGui::Button("No")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDNO;
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDCANCEL;
				}
				break;
			case MB_RETRYCANCEL:
				if (ImGui::Button("Retry")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDRETRY;
				}
				ImGui::SameLine();
				if (ImGui::Button("Cancel")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDCANCEL;
				}
				break;
			case MB_CANCELTRYCONTINUE:
				if (ImGui::Button("Cancel")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDCANCEL;
				}
				ImGui::SameLine();
				if (ImGui::Button("Try Again")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDTRYAGAIN;
				}
				ImGui::SameLine();
				if (ImGui::Button("Continue")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDCONTINUE;
				}
				break;
			case MB_ABORTRETRYIGNORE:
				if (ImGui::Button("Abort")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDABORT;
				}
				ImGui::SameLine();
				if (ImGui::Button("Retry")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDRETRY;
				}
				ImGui::SameLine();
				if (ImGui::Button("Ignore")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDIGNORE;
				}
				break;
			case MB_OK:
				__fallthrough;
			default:
				if (ImGui::Button("OK")) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = IDOK;
				}
			}
			ImGui::EndPopup();
		}
	}

	if (!pImGuiWindow) pImGuiWindow = ImGui::GetCurrentWindow();
	ImGui::End();
}

bool BeginGUI() {
	if (bInitialized)
		return false;
	bInitialized = true;

	// Initialize
	if (!glfwInit()) return false;
	if (!ImGui::CreateContext()) return false;
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
	if (!io.Fonts->Build()) return false;

	// Create window
	glfwWindowHint(GLFW_RESIZABLE, 0);
	glfwWindowHint(GLFW_DECORATED, 0);
	glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, 1);
	GLFWwindow* pWindow = glfwCreateWindow(width, height, "Yet Another Packer", NULL, NULL);
	Data.hWnd = glfwGetWin32Window(pWindow);
	int x, y, mon_x, mon_y;
	glfwGetMonitorWorkarea(glfwGetPrimaryMonitor(), &x, &y, &mon_x, &mon_y);
	glfwSetWindowPos(pWindow, x + (mon_x - width) / 2, y + (mon_y - height) / 2);
	glfwMakeContextCurrent(pWindow);
	glfwSwapInterval(1);
	ImGui_ImplGlfw_InitForOpenGL(pWindow, true);
	ImGui_ImplOpenGL3_Init();

	// Main loop
	while (bOpen && !glfwWindowShouldClose(pWindow)) {
		// Prepare
		glfwPollEvents();
		ImGui_ImplGlfw_NewFrame();
		ImGui_ImplOpenGL3_NewFrame();
		ImGui::NewFrame();

		if (pImGuiWindow) {
			// Minimize window
			if (pImGuiWindow->Collapsed) {
				glfwIconifyWindow(pWindow);
			}

			// Move window
			if (pImGuiWindow->Pos.x != 0 || pImGuiWindow->Pos.y != 0) {
				int x = 0;
				int y = 0;
				glfwGetWindowPos(pWindow, &x, &y);
				x += pImGuiWindow->Pos.x;
				y += pImGuiWindow->Pos.y;
				glfwSetWindowPos(pWindow, x, y);
			}
		}
		
		if (ImGui::IsKeyDown(ImGuiKey_LeftCtrl) || ImGui::IsKeyDown(ImGuiKey_RightCtrl)) {
			// Ctrl + N
			if (ImGui::IsKeyDown(ImGuiKey_N)) {
				OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
				SaveProject();
			}

			// Ctrl + O
			if (ImGui::IsKeyDown(ImGuiKey_O)) {
				OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false);
				LoadProject();
			}

			// Ctrl + (Shift) + S
			if (ImGui::IsKeyDown(ImGuiKey_S)) {
				if (ImGui::IsKeyDown(ImGuiKey_LeftShift) || ImGui::IsKeyDown(ImGuiKey_RightShift)) {
					OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
				}
				SaveProject();
			}
		}

		// Render
		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(width, height));
		ImGui::SetNextWindowCollapsed(false, ImGuiCond_Always);
		DrawGUI();

		// Finish frame
		ImGui::Render();
		ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
		glfwSwapBuffers(pWindow);
	}

	// Shutdown
	glfwDestroyWindow(pWindow);
	pImGuiWindow = (ImGuiWindow*)1;
	ImGui_ImplGlfw_Shutdown();
	ImGui_ImplOpenGL3_Shutdown();
	glfwTerminate();
	bInitialized = false;
	return true;
}

int Modal(_In_ char* pText, _In_ char* pTitle, _In_ UINT uType) {
	if (!pText || !Data.hWnd) return 0;

	// Wait for other modals
	HANDLE hMutex = CreateMutexA(NULL, FALSE, "YAP_Modal");
	WaitForSingleObject(hMutex, INFINITE);

	// Create modal
	CurrentModal.pText = pText;
	CurrentModal.pTitle = pTitle;
	CurrentModal.uType = uType;
	if (uType == MB_OK) {
		ReleaseMutex(hMutex);
		return IDOK;
	}
	while (CurrentModal.pText) Sleep(100);
	ReleaseMutex(hMutex);
	return CurrentModal.uType;
}

void ApplyImGuiTheme() {
	ImGuiStyle& style = ImGui::GetStyle();

	style.Alpha = 1.0f;
	style.DisabledAlpha = 0.6f;
	style.WindowPadding = ImVec2(8.0f, 8.0f);
	style.WindowRounding = 10.0f;
	style.WindowBorderSize = 0.0f;
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
	style.Colors[ImGuiCol_TextLink] = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
	style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_DragDropTarget] = ImVec4(1.0f, 1.0f, 0.0f, 0.8999999761581421f);
	style.Colors[ImGuiCol_NavHighlight] = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);
	style.Colors[ImGuiCol_NavWindowingHighlight] = ImVec4(1.0f, 1.0f, 1.0f, 0.699999988079071f);
	style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.800000011920929f, 0.800000011920929f, 0.800000011920929f, 0.2000000029802322f);
	style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.800000011920929f, 0.800000011920929f, 0.800000011920929f, 0.3499999940395355f);

	// Invert
	if (Settings.bLight) {
		for (int i = 0; i < ImGuiCol_COUNT; i++) {
			style.Colors[i] = ImVec4(1.f - style.Colors[i].x, 1.f - style.Colors[i].y, 1.f - style.Colors[i].z, style.Colors[i].w);
		}
	}
}