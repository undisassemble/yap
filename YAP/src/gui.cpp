/*!
 * @file gui.cpp
 * @author undisassemble
 * @brief GUI functions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#include "imgui.h"
#include "util.hpp"
#define GLFW_EXPOSE_NATIVE_WIN32
#include "gui.hpp"
#include "font.hpp"
#include "icons.hpp"
#include "theme.hpp"
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include <ctime>
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "asm.hpp"
#include <Zycore/Zycore.h>

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

#ifdef _DEBUG
void DebugWarning() {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_WARNING]);
	ImGui::Text(ICON_BUG);
	ImGui::PopStyleColor();
	ImGui::SetItemTooltip("This feature is experimental, use with caution!");
}
#endif

void FeatureWarning(_In_ char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_WARNING]);
	ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip(text);
}

void FeatureInfo(_In_ char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_INFO]);
	ImGui::Text(ICON_CIRCLE_INFO);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip(text);
}

void DrawGUI() {
// Dont do anything if window is not shown
	if (!bOpen || bMinimized) return;
	
	ImGui::Begin("Yet Another Packer", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoTitleBar);

	// Menu bar
	if (ImGui::BeginMenuBar()) {
		ImGui::Text("Yet Another Packer    |");
		if (ImGui::BeginMenu("File")) {
			if (ImGui::MenuItem(ICON_FILE " New", "Ctrl + N")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			if (ImGui::MenuItem(ICON_FOLDER_OPEN " Open", "Ctrl + O")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false); LoadProject(); }
			if (!Data.Project[0]) ImGui::BeginDisabled();
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save", "Ctrl + S")) { SaveProject(); }
			if (!Data.Project[0]) ImGui::EndDisabled();
			if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save as", "Ctrl + Shift + S")) { OpenFileDialogue(Data.Project, sizeof(Data.Project), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveProject(); }
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Settings")) {
			if (ImGui::BeginMenu(ICON_PALETTE " Theme")) {
#define ADD_MENU_THEME(name, icon, id) if (ImGui::MenuItem(name, icon, Settings.Theme == id)) { Settings.Theme = id; ApplyImGuiTheme(); SaveSettings(); }
				ADD_MENU_THEME("Default Dark", ICON_MOON, 0);
				ADD_MENU_THEME("Open Dark", ICON_MOON, 1);
				ADD_MENU_THEME("Open Light", ICON_SUN, 2);
				ADD_MENU_THEME("Catppuccin Latte", ICON_SUN, 3);
				ADD_MENU_THEME("Catppuccin Frappé", ICON_MOON, 4);
				ADD_MENU_THEME("Catppuccin Macchiato", ICON_MOON, 5);
				ADD_MENU_THEME("Catppuccin Mocha", ICON_MOON, 6);
#undef ADD_MENU_THEME
				ImGui::EndMenu();
			}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("About")) {
			if (ImGui::MenuItem(ICON_CIRCLE_QUESTION " Feature help")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/Features.md", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/LICENSE", NULL, NULL, 0); }
			ImGui::EndMenu();
		}
		//ImGui::SetCursorPos(ImVec2((width - ImGui::CalcTextSize("Yet Another Packer").x) / 2, 0));
		//ImGui::Text("Yet Another Packer");
		if (ImGui::CollapseButton(ImGui::GetCurrentWindow()->GetID("#COLLAPSE"), ImVec2(802, 3))) { ImGui::GetCurrentWindow()->Collapsed = !ImGui::GetCurrentWindow()->Collapsed; }
		if (ImGui::CloseButton(ImGui::GetCurrentWindow()->GetID("#CLOSE"), ImVec2(824, 3))) { bOpen = false; }
		ImGui::EndMenuBar();
	}
	
	// Configuration menu
	if (!Data.bRunning) {
		ImGui::BeginTabBar("#Tabs");

		if (ImGui::BeginTabItem(ICON_BOX_ARCHIVE " Packing")) {
			IMGUI_TOGGLE("Enable Packer", Options.Packing.bEnabled);
			ImGui::SetItemTooltip("Wraps the original binary with a custom loader.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Don't pack resources", Options.Packing.bDontCompressRsrc);
			ImGui::SetItemTooltip("Preserves everything in the resource directory, keeping details such as icons and privileges.");
			ImGui::SliderInt("Depth", &Options.Packing.EncodingCounts, 1, 10);
			ImGui::SetItemTooltip("Number of times the application should be packed.\n1: packed app\n2: packed packed app\n3: packed packed packed app\netc.");
			ImGui::SliderInt("Compression level", &Options.Packing.CompressionLevel, 1, 9);
			ImGui::SetItemTooltip("How compressed the binary should be.");
			ImGui::SliderInt("Mutation level", &Options.Packing.MutationLevel, 1, 5);
			ImGui::SetItemTooltip("The amount of garbage that should be generated (more -> slower).");
			IMGUI_TOGGLE("Hide IAT", Options.Packing.bHideIAT);
			ImGui::SetItemTooltip("Attempts to hide the packed binaries IAT.");
			ImGui::SameLine();
			IMGUI_TOGGLE("API emulation", Options.Packing.bAPIEmulation);
			ImGui::SetItemTooltip("Emulate some simple WINAPI functions.\n");
			IMGUI_TOGGLE("Delayed entry point", Options.Packing.bDelayedEntry);
			ImGui::SetItemTooltip("Changes the behavior of the entry point before it is run.");
			IMGUI_TOGGLE("DLL sideloading mitigations", Options.Packing.bMitigateSideloading);
			ImGui::SetItemTooltip("Prioritizes DLLs in Windows directories, loading those first instead of DLLs placed in the local directory.");
			ImGui::SameLine();
			IMGUI_TOGGLE("Only load microsoft signed DLLs", Options.Packing.bOnlyLoadMicrosoft);
			ImGui::SetItemTooltip("Only allows DLLs that have been signed by Microsoft to be loaded.");
			IMGUI_TOGGLE("Direct syscalls", Options.Packing.bDirectSyscalls);
			ImGui::SetItemTooltip("Skips use of some windows API functions and instead makes calls directly to the kernel, can break with future Windows updates.");
			IMGUI_TOGGLE("Anti-dump", Options.Packing.bAntiDump);
			ImGui::SetItemTooltip("Prevent PE dumpers and reconstructors from dumping the running process.");
			FeatureInfo("If enabled, you must use GetSelf() instead of GetModuleHandleA(NULL) to get the applications base address.");
			IMGUI_TOGGLE("Anti-debug", Options.Packing.bAntiDebug);
			ImGui::SetItemTooltip("Prevent debuggers from attaching to process.");
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-patch", Options.Packing.bAntiPatch));
			DEBUG_ONLY(ImGui::SetItemTooltip("Verify signature of binary before loading.\n"));
			DEBUG_ONLY(DebugWarning());
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-VM", Options.Packing.bAntiVM));
			DEBUG_ONLY(ImGui::SetItemTooltip("Prevent app from running in a virtual machine."));
			DEBUG_ONLY(ImGui::SameLine());
			DEBUG_ONLY(IMGUI_TOGGLE("Allow Hyper-V", Options.Packing.bAllowHyperV));
			DEBUG_ONLY(ImGui::SetItemTooltip("Still run if the detected VM is only MS Hyper-V."));
			DEBUG_ONLY(DebugWarning());
			DEBUG_ONLY(IMGUI_TOGGLE("Anti-sandbox", Options.Packing.bAntiSandbox));
			DEBUG_ONLY(ImGui::SetItemTooltip("Prevent app from running in a sandboxed environment."));
			DEBUG_ONLY(DebugWarning());
			DEBUG_ONLY(if (Options.Packing.bDelayedEntry && Options.Packing.Immitate == ExeStealth) Options.Packing.Immitate = YAP);
			DEBUG_ONLY(if (!Options.Reassembly.bEnabled) ImGui::BeginDisabled());
			DEBUG_ONLY(IMGUI_TOGGLE("Partial unpacking", Options.Packing.bPartialUnpacking));
			DEBUG_ONLY(ImGui::SetItemTooltip(Options.Reassembly.bEnabled ? "Only allows one function to be loaded at a time, preventing the whole program from being dumped at once." : "Requires reassembler to be enabled"));
			DEBUG_ONLY(FeatureWarning("This feature is not threadsafe, and only works on single threaded apps."));
			DEBUG_ONLY(DebugWarning());
			DEBUG_ONLY(if (!Options.Reassembly.bEnabled) ImGui::EndDisabled());
			ImGui::Combo("Immitate packer", (int*)&Options.Packing.Immitate, Options.Packing.bDelayedEntry ? "None\0Themida\0WinLicense\0UPX\0MPRESS\0Enigma\0" : "None\0Themida\0WinLicense\0UPX\0MPRESS\0Enigma\0ExeStealth\0");
			ImGui::SetItemTooltip("Changes some details about the packed binary to make it look like another packer.");
			IMGUI_TOGGLE("Enable process masquerading", Options.Packing.bEnableMasquerade);
			ImGui::SetItemTooltip("Makes the packed executable appear as a different process (NOT process hollowing).\nPlease note that the smaller the path the easier it is to use.");
			ImGui::SameLine();
			ImGui::SetNextItemWidth(width / 2);
			ImGui::InputText(" ", Options.Packing.Masquerade, MAX_PATH);
			ImGui::SameLine();
			if (ImGui::Button("Scramble")) {
				ZeroMemory(Options.Packing.Masquerade, sizeof(Options.Packing.Masquerade));
				for (int i = 0, n = rand() % 32; i < n; i++) {
					Options.Packing.Masquerade[i] = rand() & 0xFF;
					if (!Options.Packing.Masquerade[i]) break;
				}
			}
			ImGui::SetItemTooltip("Set to randomized string.");
			DEBUG_ONLY(IMGUI_TOGGLE("Mark critical (requires admin)", Options.Packing.bMarkCritical));
			DEBUG_ONLY(ImGui::SetItemTooltip("Marks the process as critical, causing the system to bluescreen when the process crashes or is killed.\nRequires the packed process to be run with administrator privileges.\n\nDoes not bluescreen if the process exits gracefully."));
			DEBUG_ONLY(DebugWarning());
			ImGui::InputText("Leave a message", Options.Packing.Message, 64);
			ImGui::SetItemTooltip("Leave a little message for any possible reverse engineers.");
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem(ICON_CODE " Reassembler")) {
			IMGUI_TOGGLE("Enabled", Options.Reassembly.bEnabled);
			ImGui::SetItemTooltip("Disassembles your application, and assembles a new modified version.");
			ImGui::SliderInt("Mutation level", &Options.Reassembly.MutationLevel, 0, 4);
			ImGui::SetItemTooltip("How much garbage code should be inserted between real code (more -> slower).");
			IMGUI_TOGGLE("Remove useless data", Options.Reassembly.bRemoveData);
			ImGui::SetItemTooltip("Removes some data from the PE headers.");
			IMGUI_TOGGLE("Strip debug symbols", Options.Reassembly.bStrip);
			ImGui::SetItemTooltip("Remove debugging information from the PE.");
			IMGUI_TOGGLE("Strip DOS stub", Options.Reassembly.bStripDOSStub);
			ImGui::SetItemTooltip("Remove DOS stub from the PE.");
			IMGUI_TOGGLE("Instruction substitution", Options.Reassembly.bSubstitution);
			ImGui::SetItemTooltip("Replaces some existing instructions with other, more complicated alternatives.");
			ImGui::InputScalar("Rebase image", ImGuiDataType_U64, &Options.Reassembly.Rebase, NULL, NULL, "%p", ImGuiInputTextFlags_CharsHexadecimal);
			ImGui::SetItemTooltip("Changes images prefered base address. (0 to disable)");
			ImGui::EndTabItem();
		}

#ifdef _DEBUG
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
#endif

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
				ImGui::DragScalar("UPX version", ImGuiDataType_U8, &Options.Advanced.UPXVersionPatch, 1.f, &MIN, &MAX);
				ImGui::PopStyleVar();
				ImGui::PopItemWidth();
				IMGUI_TOGGLE("Fake symbol table", Options.Advanced.bFakeSymbols);
				IMGUI_TOGGLE("Mutate", Options.Advanced.bMutateAssembly);
				FeatureWarning("I highly recommend keeping this setting enabled.");
				IMGUI_TOGGLE("Semi-random section names", Options.Advanced.bSemiRandomSecNames);
				IMGUI_TOGGLE("Full-random section names", Options.Advanced.bTrueRandomSecNames);
				ImGui::InputText("Section 1 name", Options.Advanced.Sec1Name, 9);
				ImGui::InputText("Section 2 name", Options.Advanced.Sec2Name, 9);
				ImGui::TreePop();
			}
			if (ImGui::TreeNode("VM")) {
				IMGUI_TOGGLE("Delete virtualized functions", Options.Advanced.bDeleteVirtualizedFunctions);
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
#ifdef ENABLE_DUMPING
			IMGUI_TOGGLE("Dump disassembly", Options.Debug.bDumpAsm);
#endif
			IMGUI_TOGGLE("Dump individual sections", Options.Debug.bDumpSections);
			IMGUI_TOGGLE("Dump function ranges", Options.Debug.bDumpFunctions);
			IMGUI_TOGGLE("Create breakpoints", Options.Debug.bGenerateBreakpoints);
			IMGUI_TOGGLE("Wrap real instructions in NOPs", Options.Debug.bGenerateMarks);
			IMGUI_TOGGLE("Strict mutation", Options.Debug.bStrictMutation);
			IMGUI_TOGGLE("Disable relocations", Options.Debug.bDisableRelocations);
			if (ImGui::Button("Test error")) Modal("Test error", "Error", MB_OK | MB_ICONERROR);
			ImGui::SameLine();
			if (ImGui::Button("Test warning")) Modal("Test warning", "Warning", MB_OK | MB_ICONWARNING);
			ImGui::SameLine();
			if (ImGui::Button("Test info")) Modal("Test info", "Information", MB_OK | MB_ICONINFORMATION);
			
			// TODO: Avoid looking at this for the foreseeable future
			ImGui::Text("DecodedInstruction reduction: %d bytes (%.2f%%)", (int64_t)sizeof(DecodedInstruction) - sizeof(ZydisDecodedInstruction), 100.f * (int64_t)((int64_t)sizeof(DecodedInstruction) - sizeof(ZydisDecodedInstruction)) / (int64_t)sizeof(ZydisDecodedInstruction));
			ImGui::Text("DecodedOperand reduction: %d bytes (%.2f%%)", (int64_t)sizeof(DecodedOperand) - sizeof(ZydisDecodedOperand), 100.f * (int64_t)((int64_t)sizeof(DecodedOperand) - sizeof(ZydisDecodedOperand)) / (int64_t)sizeof(ZydisDecodedOperand));
			ImGui::Text("Total memory reduction (per line): %d bytes (%.2f%%)", (int64_t)(sizeof(DecodedOperand) + sizeof(DecodedInstruction)) - (sizeof(ZydisDecodedOperand) + sizeof(ZydisDecodedInstruction)), 100.f * (int64_t)((sizeof(DecodedOperand) + sizeof(DecodedInstruction)) - (sizeof(ZydisDecodedOperand) + sizeof(ZydisDecodedInstruction))) / (int64_t)(sizeof(Line) - sizeof(DecodedInstruction) - sizeof(DecodedOperand) * 4 + sizeof(ZydisDecodedInstruction) + sizeof(ZydisDecodedOperand) * 4));
			
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
			ImGui::Text("Zycore: %d.%d.%d", ZYCORE_VERSION_MAJOR(ZYCORE_VERSION), ZYCORE_VERSION_MINOR(ZYCORE_VERSION), ZYCORE_VERSION_PATCH(ZYCORE_VERSION));
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
				Modal("Failed to get file name", "Error", MB_OK | MB_ICONERROR);
				LOG(Failed, MODULE_YAP, "Failed to open file dialogue: %d\n", CommDlgExtendedError());
			} else {
				pAssembly = new Asm(file);
				if (pAssembly->Status) {
					Modal("Unable to parse binary\n", "Error", MB_OK | MB_ICONERROR);
					LOG(Failed, MODULE_YAP, "Failed to parse binary (%d)\n", pAssembly->Status);
					delete pAssembly;
					pAssembly = NULL;
				} else {
					CreateThread(0, 0, Begin, 0, 0, 0);
				}
			}
		}
	}

	// Data
	else {
		ImGui::SeparatorText("Overall");
		ImGui::Text("Memory Usage Status (%d KB committed)", Data.Reserved / 1000);
		ImGui::SameLine();
		ImGui::ProgressBar(Data.Reserved ? ((double)Data.InUse / Data.Reserved) : (double)0);
		switch (Data.State) {
		case Packing:
			ImGui::SeparatorText("Packing");
			break;
		case Disassembling:
			ImGui::SeparatorText("Disassembling");
			break;
		case Assembling:
			ImGui::SeparatorText("Assembling");
			break;
		default:
			ImGui::Separator();
		}
		ImGui::Text("Total progress");
		ImGui::SameLine();
		ImGui::ProgressBar(Data.fTotalProgress);
		ImGui::Text("Task: %s", Data.sTask);
		ImGui::Text("Task progress");
		ImGui::SameLine();
		ImGui::ProgressBar(Data.fTaskProgress);
	}

	// Modals
	if (CurrentModal.pText) {
		ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), 0, ImVec2(0.5f, 0.5f));
		ImGui::OpenPopup(CurrentModal.pTitle);
		if (ImGui::BeginPopupModal(CurrentModal.pTitle, NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
			switch (CurrentModal.uType & MB_ICONMASK) {
			case MB_ICONERROR:
				ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_ERROR]);
				ImGui::Text(ICON_CIRCLE_EXCLAMATION);
				ImGui::PopStyleColor();
				ImGui::SameLine();
				break;
			case MB_ICONINFORMATION:
				ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_INFO]);
				ImGui::Text(ICON_CIRCLE_INFO);
				ImGui::PopStyleColor();
				ImGui::SameLine();
				break;
			case MB_ICONWARNING:
				ImGui::PushStyleColor(ImGuiCol_Text, Themes[Settings.Theme][THEME_COL_WARNING]);
				ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
				ImGui::PopStyleColor();
				ImGui::SameLine();
			}
			
			ImGui::Text(CurrentModal.pText);

			// Beautiful, isnt it?
			switch (CurrentModal.uType & MB_TYPEMASK) {
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
	ImGuiStyle& style = ImGui::GetStyle();
	style.WindowRounding = 10.0f;
	style.WindowBorderSize = 0.0f;
	style.FrameRounding = 5.0f;
	style.GrabMinSize = 10.0f;
	style.GrabRounding = 5.0f;

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
	if ((uType & MB_TYPEMASK) == MB_OK) {
		ReleaseMutex(hMutex);
		return IDOK;
	}
	while (CurrentModal.pText) Sleep(100);
	ReleaseMutex(hMutex);
	return CurrentModal.uType;
}

void ApplyImGuiTheme() {
	ImGuiStyle& style = ImGui::GetStyle();
	for (int i = 0; i < ImGuiCol_COUNT; i++) {
		style.Colors[i] = Themes[Settings.Theme][i];
	}
}