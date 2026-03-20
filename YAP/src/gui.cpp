/*!
 * @file gui.cpp
 * @author undisassemble
 * @brief GUI functions
 * @version 0.0.0
 * @date 2026-03-20
 * @copyright MIT License
 * 
 * @todo Feature search
 */

#include "imgui.h"
#include "util.hpp"
#define GLFW_EXPOSE_NATIVE_WIN32
#include "gui.hpp"
#include "font.hpp"
#include "icons.hpp"
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include <ctime>
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "relib/asm.hpp"
#include <Zycore/Zycore.h>
#include <array>

// Globals
bool bMinimized = false, bOpen = true, bInitialized = false;
int iGuiWidth = 850;
int iGuiHeight = 560;
float fGuiScale = 1.f;
ImGuiWindow* pImGuiWindow = NULL;
extern Asm* pAssembly;
ImVec4 fBgColTopLeft = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
ImVec4 fBgColTopRight = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
ImVec4 fBgColBotLeft = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
ImVec4 fBgColBotRight = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
uint8_t u8CurrentCategory = 0;
struct {
	char* pTitle = NULL;
	char* pText = NULL;
	UINT uType = 0;
} CurrentModal;

using namespace GUI;

std::vector<std::pair<const char*, WidgetClasses::Base*>> GUI::Widgets;

// Opens file dialogue
bool GUI::OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo) {
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

void DrawGUI() {
	// Dont do anything if window is not shown
	if (!bOpen || bMinimized) return;
	
	ImGui::Begin("Yet Another Packer", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::GetBackgroundDrawList()->AddRectFilledMultiColor(ImVec2(0, 0), ImVec2(iGuiWidth, iGuiHeight), ImGui::GetColorU32(fBgColTopLeft), ImGui::GetColorU32(fBgColTopRight), ImGui::GetColorU32(fBgColBotRight), ImGui::GetColorU32(fBgColBotLeft));

	// Menu bar
	ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(ImGui::GetWindowWidth(), 25), ImGui::GetColorU32(ImGuiCol_MenuBarBg));
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetStyle().WindowPadding.x, (25 - ImGui::GetTextLineHeight()) / 2), ImGui::GetColorU32(ImGuiCol_Text), "Yet Another Packer");
	
	// Close button
	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowWidth() - 40, 0));
	if (ImGui::InvisibleButton("WindowClose", ImVec2(40, 25))) {
		bOpen = false;
	} else if (ImGui::IsItemHovered()) {
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(ImGui::GetWindowWidth() - 40, 0), ImVec2(ImGui::GetWindowWidth(), 25), ImGui::GetColorU32(ImVec4(188, 0, 0, 255)));
	}
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetWindowWidth() - 40 + (40 - ImGui::CalcTextSize(ICON_WINDOW_CLOSE).x) / 2, 1 + (25 - ImGui::GetTextLineHeight()) / 2), ImGui::GetColorU32(ImGuiCol_Text), ICON_WINDOW_CLOSE);
	
	// Minimize button
	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowWidth() - 80, 0));
	if (ImGui::InvisibleButton("WindowMinimize", ImVec2(40, 25))) {
		ImGui::GetCurrentWindow()->Collapsed = true;
	} else if (ImGui::IsItemHovered()) {
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(ImGui::GetWindowWidth() - 80, 0), ImVec2(ImGui::GetWindowWidth() - 40, 25), ImGui::GetColorU32(ImVec4(0.7f, 0.7f, 0.7f, 0.2f)));
	}
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetWindowWidth() - 80 + (40 - ImGui::CalcTextSize(ICON_WINDOW_MINIMIZE).x) / 2, 1 + (25 - ImGui::GetTextLineHeight()) / 2), ImGui::GetColorU32(ImGuiCol_Text), ICON_WINDOW_MINIMIZE);

	ImGui::SetCursorPosY(25 + ImGui::GetStyle().WindowPadding.y);
	// if (ImGui::BeginMenuBar()) {
	// 	ImGui::Text("Yet Another Packer    |");
	// 	if (ImGui::BeginMenu("File")) {
	// 		if (ImGui::MenuItem(ICON_FILE " New", "Ctrl + N")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveConfig(); }
	// 		if (ImGui::MenuItem(ICON_FOLDER_OPEN " Open", "Ctrl + O")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false); LoadConfig(); }
	// 		if (!Data.ConfigPath[0]) ImGui::BeginDisabled();
	// 		if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save", "Ctrl + S")) { SaveConfig(); }
	// 		if (!Data.ConfigPath[0]) ImGui::EndDisabled();
	// 		if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save as", "Ctrl + Shift + S")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveConfig(); }
	// 		ImGui::EndMenu();
	// 	}
	// 	if (ImGui::BeginMenu("About")) {
	// 		if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
	// 		if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open Website")) { ShellExecuteA(Data.hWnd, "open", "https://undisassemble.dev/yap", NULL, NULL, 0); }
	// 		if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/LICENSE", NULL, NULL, 0); }
	// 		ImGui::EndMenu();
	// 	}
	// 	//ImGui::SetCursorPos(ImVec2((width - ImGui::CalcTextSize("Yet Another Packer").x) / 2, 0));
	// 	//ImGui::Text("Yet Another Packer");
	// 	if (ImGui::CollapseButton(ImGui::GetCurrentWindow()->GetID("#COLLAPSE"), ImVec2(iGuiWidth - 48 * fGuiScale, 3))) { ImGui::GetCurrentWindow()->Collapsed = !ImGui::GetCurrentWindow()->Collapsed; }
	// 	if (ImGui::CloseButton(ImGui::GetCurrentWindow()->GetID("#CLOSE"), ImVec2(iGuiWidth - 26 * fGuiScale, 3))) { bOpen = false; }
	// 	ImGui::EndMenuBar();
	// }
	
	// Configuration menu
	if (!Data.bRunning) {
		// Category selection
		const float fBtnWidth = ((float)iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2 - ImGui::GetStyle().ItemSpacing.x * (Widgets.size() - 1)) / Widgets.size();
		ImGui::PushFont(NULL, ImGui::GetFontSize() * 1.25);
		for (int i = 0; i < GUI::Widgets.size(); i++) {
			ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(u8CurrentCategory == i ? ImGuiCol_ButtonActive : ImGuiCol_Button));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::GetStyleColorVec4(u8CurrentCategory == i ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered));
			if (ImGui::Button(GUI::Widgets[i].first, ImVec2(fBtnWidth, 50))) u8CurrentCategory = i;
			ImGui::PopStyleColor(2);
			ImGui::SameLine();
		}
		ImGui::PopFont();
		ImGui::NewLine();

		// Category contents
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y);
		ImGui::BeginChild("#TabContents", ImVec2(iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2, iGuiHeight - ImGui::GetStyle().WindowPadding.y - ImGui::GetCursorPosY()));
		
		#ifdef _DEBUG
		if (u8CurrentCategory == 3) { // Style editor (temp)
			ImGui::ColorEdit4("Background Gradient Bottom Left", (float*)&fBgColBotLeft);
			ImGui::ColorEdit4("Background Gradient Bottom Right", (float*)&fBgColBotRight);
			ImGui::ColorEdit4("Background Gradient Top Left", (float*)&fBgColTopLeft);
			ImGui::ColorEdit4("Background Gradient Top Right", (float*)&fBgColTopRight);
			ImGui::ShowStyleEditor();
		} else
		#endif

		if (u8CurrentCategory < Widgets.size()) {
			WidgetClasses::Base *pChild, *pItem = Widgets[u8CurrentCategory].second;
			while (pItem) {
				pItem->Render();
				if (pItem->ShouldShowChildren()) {
					ImGui::BeginDisabled(pItem->AreChildrenDisabled());
					pChild = pItem->GetChildren();
					while (pChild) {
						pChild->Render();
						pChild = pChild->GetNextWidget();
					}
					ImGui::EndDisabled();
				}
				pItem = pItem->GetNextWidget();
			}
		} else {
			ImGui::Text("I don't know how but this broke, tried to load tab %hhu which doesn't exist", u8CurrentCategory);
		}

		ImGui::EndChild();
	}

	// Data
	else {
		ImGui::SeparatorText("Memory");
		ImGui::Text("Memory Usage Status (%.2f MB committed)", (ReLibMetrics.Memory.ByBuffer) / 1000000.f);
		ImGui::SameLine();
		ImGui::ProgressBar(ReLibMetrics.Memory.ByVector ? ((double)ReLibMetrics.Memory.VectorUsed / ReLibMetrics.Memory.ByVector) : (double)0);
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
		ImGui::ProgressBar((Data.State == Assembling || Data.State == Disassembling) ? pAssembly->fProgress : Data.fTotalProgress);
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
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(228, 83, 83, 255));
				ImGui::Text(ICON_CIRCLE_EXCLAMATION);
				ImGui::PopStyleColor();
				ImGui::SameLine();
				break;
			case MB_ICONINFORMATION:
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(152, 205, 253, 255));
				ImGui::Text(ICON_CIRCLE_INFO);
				ImGui::PopStyleColor();
				ImGui::SameLine();
				break;
			case MB_ICONWARNING:
				ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(227, 185, 104, 255));
				ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
				ImGui::PopStyleColor();
				ImGui::SameLine();
			}
			
			ImGui::Text("%s", CurrentModal.pText);

			// Modal buttons
			const std::vector<std::pair<const char*, UINT>> modals[] = {
				{ { "OK", IDOK } }, // MB_OK
				{ { "OK", IDOK }, { "Cancel", IDCANCEL } }, // MB_OKCANCEL
				{ { "Abort", IDABORT }, { "Retry", IDRETRY }, { "Ignore", IDIGNORE } }, // MB_ABORTRETRYIGNORE
				{ { "Yes", IDYES }, { "No", IDNO }, { "Cancel", IDCANCEL } }, // MB_YESNOCANCEL
				{ { "Yes", IDYES }, { "No", IDNO } }, // MB_YESNO
				{ { "Retry", IDRETRY }, { "Cancel", IDCANCEL } }, // MB_RETRYCANCEL
				{ { "Cancel", IDCANCEL }, { "Try Again", IDTRYAGAIN }, { "Continue", IDCONTINUE } }, // MB_CANCELTRYCONTINUE
			};
			RELIB_ASSERT((CurrentModal.uType & MB_TYPEMASK) < countof(modals));
			for (std::pair<const char*, UINT> btn : modals[CurrentModal.uType & MB_TYPEMASK]) {
				if (ImGui::Button(btn.first)) {
					ImGui::CloseCurrentPopup();
					CurrentModal.pText = NULL;
					CurrentModal.uType = btn.second;
				}
			}
			ImGui::EndPopup();
		}
	}

	if (!pImGuiWindow) pImGuiWindow = ImGui::GetCurrentWindow();
	ImGui::End();
}

void GLFWErrorHandler(int error, const char* message) {
	LOG(Failed, MODULE_YAP, "GLFW error %d: %s\n", error, message);
}

bool GUI::Begin() {
	if (bInitialized)
		return false;
	bInitialized = true;

	// Initialize
	glfwSetErrorCallback(GLFWErrorHandler);
	if (!glfwInit()) return false;
	if (!ImGui::CreateContext()) return false;
	ImGuiIO& io = ImGui::GetIO();
	io.ConfigFlags = ImGuiConfigFlags_NavEnableKeyboard;
	io.IniFilename = NULL;

	// Setup style
	ImGuiStyle& style = ImGui::GetStyle();
	style.Colors[ImGuiCol_WindowBg] = ImColor(25, 25, 25, 0);
	style.Colors[ImGuiCol_PopupBg] = ImColor(20, 20, 20, 240);
	style.Colors[ImGuiCol_FrameBg] = ImColor(40, 40, 40, 255);
    style.Colors[ImGuiCol_FrameBgHovered] = ImColor(60, 60, 60, 255);
    style.Colors[ImGuiCol_FrameBgActive] = ImColor(75, 75, 75, 255);
	style.Colors[ImGuiCol_TitleBg] = ImColor(25, 25, 25, 255);
    style.Colors[ImGuiCol_TitleBgActive] = ImColor(25, 25, 25, 255);
	style.Colors[ImGuiCol_MenuBarBg] = ImColor(35, 35, 35, 255);
	style.Colors[ImGuiCol_ScrollbarGrab] = ImColor(75, 75, 75, 255);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImColor(130, 130, 130, 255);
    style.Colors[ImGuiCol_CheckMark] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_SliderGrab] = ImColor(75, 75, 75, 255);
    style.Colors[ImGuiCol_SliderGrabActive] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_Button] = ImColor(40, 40, 40, 255);
    style.Colors[ImGuiCol_ButtonHovered] = ImColor(60, 60, 60, 255);
    style.Colors[ImGuiCol_ButtonActive] = ImColor(80, 80, 80, 255);
	style.Colors[ImGuiCol_TabHovered] = ImColor(60, 60, 60, 255);
    style.Colors[ImGuiCol_Tab] = ImColor(40, 40, 40, 255);
    style.Colors[ImGuiCol_TabSelected] = ImColor(60, 60, 60, 255);
    style.Colors[ImGuiCol_Header] = ImColor(40, 40, 40, 255);
    style.Colors[ImGuiCol_HeaderHovered] = ImColor(60, 60, 60, 255);
    style.Colors[ImGuiCol_HeaderActive] = ImColor(80, 80, 80, 255);
	style.WindowRounding = 10.0f;
	style.WindowBorderSize = 0.0f;
	style.FrameRounding = 5.0f;
	style.GrabMinSize = 10.0f;
	style.GrabRounding = 5.0f;

	// Scaling
	int x, y, mon_x, mon_y;
	glfwGetMonitorWorkarea(glfwGetPrimaryMonitor(), &x, &y, &mon_x, &mon_y);
	fGuiScale = mon_x / 1920.f;
	if (mon_y / 1080.f < fGuiScale) {
		fGuiScale = mon_y / 1080.f;
	}
	LOG(Info, MODULE_YAP, "Detected monitor size: (%d, %d)\n", mon_x, mon_y);
	LOG(Info, MODULE_YAP, "GUI scaling: %f\n", fGuiScale);
	style.ScaleAllSizes(fGuiScale);
	iGuiWidth *= fGuiScale;
	iGuiHeight *= fGuiScale;

	// Setup fonts
	io.Fonts->Clear();
	io.FontDefault = NULL;
	io.Fonts->AddFontFromMemoryCompressedTTF(font_compressed_data, font_compressed_size, 16 * fGuiScale);
	ImFontConfig config;
	config.MergeMode = true;
	config.GlyphMinAdvanceX = 16.f;
	io.Fonts->AddFontFromMemoryCompressedTTF(icons_compressed_data, icons_compressed_size, 16 * fGuiScale, &config);

	// Create window
	glfwWindowHint(GLFW_RESIZABLE, 0);
	glfwWindowHint(GLFW_DECORATED, 0);
	glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, 1);
	GLFWwindow* pWindow = glfwCreateWindow(iGuiWidth, iGuiHeight, "Yet Another Packer", NULL, NULL);
	if (!pWindow) return false;
	Data.hWnd = glfwGetWin32Window(pWindow);
	glfwSetWindowPos(pWindow, x + (mon_x - iGuiWidth) / 2, y + (mon_y - iGuiHeight) / 2);
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
				OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
				SaveConfig();
			}

			// Ctrl + O
			if (ImGui::IsKeyDown(ImGuiKey_O)) {
				OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false);
				LoadConfig();
			}

			// Ctrl + (Shift) + S
			if (ImGui::IsKeyDown(ImGuiKey_S)) {
				if (ImGui::IsKeyDown(ImGuiKey_LeftShift) || ImGui::IsKeyDown(ImGuiKey_RightShift)) {
					OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true);
				}
				SaveConfig();
			}
		}

		// Render
		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImVec2(iGuiWidth, iGuiHeight));
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

void GUI::Setup() {
	using namespace WidgetClasses;
	Widgets = {
		{
			ICON_BOX_ARCHIVE " Packing",
			(new Checkbox("Enable Packer", "Packing.bEnabled", "Wraps the original binary with a custom loader"))->WithChildren(
				1,
				new Checkbox("Don't pack resources", "Packing.bDontCompressRsrc", "Preserves everything in the resource directory, keeping details such as icons and privileges")
			)->FollowedBy(
				16,
				new Slider("Depth", "Packing.iEncodingCounts", 1, 10, "Number of times the application should be packed, slow"),
				new Slider("Compression level", "Packing.iCompressionLevel", 1, 9, "How compressed the binary should be"),
				new Slider("Mutation level", "Packing.iMutationLevel", 1, 5, "The amount of garbage that should be generated, slow"),
				new Checkbox("Hide Import Address Table", "Packing.bHideIAT", "Hides imported functions from static analysis tools"),
				new Checkbox("API emulation", "Packing.bAPIEmulation", "Replaces some WINAPI functions with custom alternatives"),
				new Checkbox("Delayed entry point", "Packing.bDelayedEntry", "Changes the behavior of the entry point before it is run"),
				new Checkbox("DLL sideloading mitigations", "Packing.bMitigateSideloading", "Prioritizes DLLs in Windows directories, loading those first instead of DLLs placed in the local directory"),
				new Checkbox("Only load Microsoft signed DLLs", "Packing.bOnlyLoadMicrosoft", "Only allows DLLs that have been signed by Microsoft to be loaded"),
				new Checkbox("Direct syscalls", "Packing.bDirectSyscalls", "Skips some WINAPI functions and makes syscalls directly, may break with Windows updates"),
				(new Checkbox("Anti-dump", "Packing.bAntiDump", "Attempts to prevent the process from being dumped"))->FeatureInfo("If enabled, you must use GetSelf() instead of GetModuleHandleA(NULL) to get the applications base address."),
				new Checkbox("Anti-debug", "Packing.bAntiDebug", "Prevent debuggers from attaching to the process"),
				(new Checkbox("Anti-VM", "Packing.bAntiVM", "Dont run the app if running in a virtual machine"))->WithChildren(
					1,
					new Checkbox("Allow Hyper-V", "Packing.bAllowHyperV", "Still run if the only detected VM is MS Hyper-V")
				),
				new Dropdown("Immitate packer", "Packing.iImmitate", "None\0Themida\0WinLicense\0UPX\0MPRESS\0Enigma\0ExeStealth\0", "Changes some details about the packed binary to make it look like another packer"),
				(new Checkbox("Process masquerading", "Packing.bEnableMasquerade", "Makes the packed executable appear as a different process"))->WithChildren(
					1,
					new InputText(" ", "Packing.sMasquerade", "Process path (shorter is better)")
				),
				(new Checkbox("Mark critical (requires admin)", "Packing.bMarkCritical", "Marks the process as critical, causing a bluescreen on crash"))->DebugWarning(),
				new InputText("Leave a message", "Packing.sMessage", "Embed a message in the output binary for anyone looking :)")
			)
		},
		{
			ICON_CODE " Reassembly",
			(new Checkbox("Enable Reassembler", "Reassembly.bEnabled", "Disassembles your application, and assembles a new modified version"))->FollowedBy(
				5,
				new Slider("Mutation level", "Reassembly.iMutationLevel", 0, 5, "How much garbage code should be inserted between real code (slow)"),
				new Checkbox("Instruction substitution", "Reassembly.bSubstitution", "Replaces some existing instructions with other, more complicated alternatives"),
				new Checkbox("Remove useless data", "Reassembly.bRemoveData", "Removes some data from the PE headers"),
				new Checkbox("Strip debug symbols", "Reassembly.bStrip", "Remove debugging information from the PE"),
				new Checkbox("Strip DOS stub", "Reassembly.bStripDOSStub", "Remove DOS stub from the PE")
			)
		},
		{
			ICON_GEARS " Advanced",
			(new Category("Packer"))->WithChildren(
				7,
				new Checkbox("Fake symbol table", "Advanced.bFakeSymbols"),
				(new Checkbox("Mutate", "Advanced.bMutateAssembly"))->FeatureWarning("Disabling will make unpacking easier"),
				(new Checkbox("Substitute", "Advanced.bEnableSubstitution"))->FeatureWarning("Disabling will make unpacking easier"),
				new Checkbox("Semi-random section names", "Advanced.bSemiRandomSecNames"),
				new Checkbox("Full-random section names", "Advanced.bTrueRandomSecNames"),
				new InputText("Section 1 name", "Advanced.sSec1Name"),
				new InputText("Section 2 name", "Advanced.sSec2Name")
			)->FollowedBy(
				1,
				(new Category("Reassembler"))->WithChildren(
					1,
					new InputScalar("Rebase image", ImGuiDataType_U64, "Advanced.u64Rebase", "Changes images prefered base address (0 to disable)", NULL, NULL, "%p", ImGuiInputTextFlags_CharsHexadecimal)
				)
			)
		},
#ifdef _DEBUG
		{
			ICON_PALETTE " Style Editor",
			{

			}
		},
		{
			ICON_BUG " Debug",
			{

			}
		}
#endif
	};
}





/***** WIDGETS ******/

using namespace WidgetClasses;

#define GetScrollbarSpace() (ImGui::GetScrollMaxY() > 0.f ? ImGui::GetStyle().WindowPadding.x + ImGui::GetCurrentWindow()->ScrollbarSizes[0] : 0)

void Base::AddNextWidget(_In_ Base* pWidget) {
	if (!pNextPeer) {
		pNextPeer = pWidget;
		return;
	}
	Base* pNext = pNextPeer;
	while (pNext->GetNextWidget()) {
		pNext = pNext->GetNextWidget();
	}
	pNext->pNextPeer = pWidget;
}

void Base::AddChild(_In_ Base* pWidget) {
	pWidget->SetIsChild();
	if (!pChildren) {
		pChildren = pWidget;
		return;
	}
	Base* pChild = pChildren;
	while (pChild->GetNextWidget()) {
		pChild = pChild->GetNextWidget();
	}
	pChild->AddNextWidget(pWidget);
}

Base* Base::WithChildren(_In_ uint32_t u8NumChildren, ...) {
	va_list args;
	va_start(args, u8NumChildren);
	for (int i = 0; i < u8NumChildren; i++) {
		AddChild(va_arg(args, Base*));
	}
	va_end(args);
	return this;
}

Base* Base::FollowedBy(_In_ uint32_t u8NumPeers, ...) {
	va_list args;
	va_start(args, u8NumPeers);
	for (int i = 0; i < u8NumPeers; i++) {
		AddNextWidget(va_arg(args, Base*));
	}
	va_end(args);
	return this;
}

void DebugWarning() {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(227, 185, 104, 255));
	ImGui::Text(ICON_BUG);
	ImGui::PopStyleColor();
	ImGui::SetItemTooltip("This feature is experimental, use with caution!");
}

void FeatureWarning(_In_ const char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(227, 185, 104, 255));
	ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip("%s", text);
}

void FeatureInfo(_In_ const char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(152, 205, 253, 255));
	ImGui::Text(ICON_CIRCLE_INFO);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip("%s", text);
}

void Base::RenderWidgetContainer(_In_ int iHeight) {
	if (~u8Flags & WIDGET_IS_CHILD) {
		if (iHeight < 0) {
			int nChildren = 1;
			if (u8Flags & WIDGET_SHOW_CHILDREN) {
				Base* pChild = this->GetChildren();
				while (pChild) {
					nChildren++;
					pChild = pChild->GetNextWidget();
				}
			}
			iHeight = ImGui::GetFrameHeight() * nChildren + ImGui::GetStyle().ItemSpacing.y * (nChildren - 1) + ImGui::GetStyle().FramePadding.y * 2;
			if (nChildren > 1 && u8Flags & WIDGET_SHOW_CHILDREN) {
				iHeight += ImGui::GetStyle().ItemSpacing.y + 1;
			}
		}

		ImVec2 tl = ImVec2(ImGui::GetStyle().WindowPadding.x, ImGui::GetCursorScreenPos().y);
		ImVec2 br = ImVec2(iGuiWidth - tl.x - GetScrollbarSpace(), tl.y + iHeight);
		ImGui::GetWindowDrawList()->AddRectFilled(tl, br, ImGui::GetColorU32(ImVec4(0.7f, 0.7f, 0.7f, 0.2f)), ImGui::GetStyle().FrameRounding);

		// Dropdown button
		if (pChildren) {
			char id[256] = { 0 };
			snprintf(id, sizeof(id), "0x%pInvisButton", this);
			float fButtonSize = ImGui::GetFrameHeight() + ImGui::GetStyle().FramePadding.y * 2;
			ImVec2 ArrowPos = ImGui::GetCursorScreenPos();
			ArrowPos.x += (fButtonSize - ImGui::GetFontSize()) / 2;
			ArrowPos.y += (fButtonSize - ImGui::GetFontSize()) / 2;
			ImGui::RenderArrow(ImGui::GetWindowDrawList(), ArrowPos, ImGui::GetColorU32(ImGuiCol_Text), (u8Flags & WIDGET_SHOW_CHILDREN) ? ImGuiDir_Down : ImGuiDir_Right);
			ImVec2 CursorPos = ImGui::GetCursorPos();
			if (ImGui::InvisibleButton(id, ImVec2(fButtonSize, fButtonSize))) {
				u8Flags ^= WIDGET_SHOW_CHILDREN;
			}
			if (ImGui::IsItemHovered()) {
				float fOpacity = ImGui::IsMouseDown(ImGuiMouseButton_Left) ? 0.4f : 0.2f;
				ImGui::GetWindowDrawList()->AddRectFilled(tl, ImVec2(tl.x + fButtonSize, tl.y + fButtonSize), ImGui::GetColorU32(ImVec4(0.7f, 0.7f, 0.7f, fOpacity)), ImGui::GetStyle().FrameRounding, ImDrawFlags_RoundCornersTopLeft | (u8Flags & WIDGET_SHOW_CHILDREN ? 0 : ImDrawFlags_RoundCornersBottomLeft));
			}
			CursorPos.x += fButtonSize;
			ImGui::SetCursorPos(CursorPos);
		}
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().FramePadding.y);
	}
	ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetStyle().FramePadding.x);
}

void Base::RenderDescription() {
	if (!pDescription) return;
	ImVec2 tpos = ImVec2(iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2 - GetScrollbarSpace() - ImGui::CalcTextSize(pDescription).x, ImGui::GetCursorScreenPos().y + ImGui::GetStyle().FramePadding.y);
	ImGui::GetWindowDrawList()->AddText(tpos, ImGui::GetColorU32(ImGuiCol_Text), pDescription);
}

void Base::EndWidgetRender() {
	if (u8Flags & WIDGET_DEBUG) { DebugWarning(); }
	if (u8Flags & WIDGET_WARNING) { FeatureWarning(pFlagText); }
	if (u8Flags & WIDGET_INFO) { FeatureInfo(pFlagText); }
	if (~u8Flags & WIDGET_IS_CHILD && pChildren && u8Flags & WIDGET_SHOW_CHILDREN) {
		ImVec2 l1 = ImVec2(ImGui::GetCursorScreenPos().x, ImGui::GetCursorScreenPos().y);
		ImVec2 l2 = ImVec2(l1.x + iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2 - GetScrollbarSpace(), l1.y + 1);
		ImGui::GetWindowDrawList()->AddRectFilled(l1, l2, ImGui::GetColorU32(ImGuiCol_Separator));
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y + 1);
	} else if (u8Flags & WIDGET_IS_CHILD ? !pNextPeer : !(pChildren && u8Flags & WIDGET_SHOW_CHILDREN)) {
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().FramePadding.y);
		ImGui::Dummy(ImVec2(0, 0));
	}
}

Checkbox::Checkbox(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pDescription) {
	RELIB_ASSERT(config.contains(pConfigName));
	this->pLabel = pLabel;
	this->pDescription = pDescription;
	pValue = &std::get<bool>(config[pConfigName]);
	if (!*pValue) u8Flags |= WIDGET_DISABLED_CHILDREN;
}

void Checkbox::Render() {
	RenderWidgetContainer();
	RenderDescription();
	if (ImGui::Checkbox(pLabel, pValue)) {
		u8Flags ^= WIDGET_DISABLED_CHILDREN;
	}
	EndWidgetRender();
};

Category::Category(_In_ const char* pLabel, _In_ const char* pDescription, _In_ bool bStartOpen) {
	this->pLabel = pLabel;
	this->pDescription = pDescription;
	if (bStartOpen) u8Flags |= WIDGET_SHOW_CHILDREN;
}

void Category::Render() {
	RenderWidgetContainer();
	RenderDescription();
	ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (ImGui::GetFrameHeight() - ImGui::GetTextLineHeight()) / 2);
	ImGui::Text("%s", pLabel);
	ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (ImGui::GetFrameHeight() - ImGui::GetTextLineHeight()) / 2 - ImGui::GetStyle().ItemSpacing.y);
	ImGui::Dummy(ImVec2(0, 0));
	EndWidgetRender();
}

Slider::Slider(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ int nMin, _In_ int nMax, _In_ const char* pDescription, _In_ const char* pFormat) {
	RELIB_ASSERT(config.contains(pConfigName));
	this->pLabel = pLabel;
	this->pValue = &std::get<int>(config[pConfigName]);
	this->nMin = nMin;
	this->nMax = nMax;
	this->pDescription = pDescription;
	this->pFormat = pFormat;
}

void Slider::Render() {
	RenderWidgetContainer();
	RenderDescription();
	ImGui::PushItemWidth(fGuiScale * 200);
	ImGui::SliderInt(pLabel, pValue, nMin, nMax, pFormat);
	EndWidgetRender();
}


Dropdown::Dropdown(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pItems, _In_ const char* pDescription) {
	RELIB_ASSERT(config.contains(pConfigName));
	this->pLabel = pLabel;
	this->pValue = &std::get<int>(config[pConfigName]);
	this->pItems = pItems;
	this->pDescription = pDescription;
}

void Dropdown::Render() {
	RenderWidgetContainer();
	RenderDescription();
	ImGui::PushItemWidth(fGuiScale * 200);
	ImGui::Combo(pLabel, pValue, pItems);
	EndWidgetRender();
}

InputText::InputText(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pDescription, _In_ ImGuiInputTextFlags Flags) {
	RELIB_ASSERT(config.contains(pConfigName));
	this->pLabel = pLabel;
	this->pBuf = &std::get<Buffer>(config[pConfigName]);
	this->pDescription = pDescription;
	this->Flags = Flags;
}

void InputText::Render() {
	RenderWidgetContainer();
	RenderDescription();
	ImGui::PushItemWidth(fGuiScale * 200);
	ImGui::InputText(pLabel, (char*)pBuf->Data(), pBuf->Size(), Flags);
	EndWidgetRender();
}

InputScalar::InputScalar(_In_ const char* pLabel, _In_ ImGuiDataType Type, _In_ const char* pConfigName, _In_ const char* pDescription, _In_ void* pStep, _In_ void* pStepFast, _In_ const char* pFormat, _In_ ImGuiInputTextFlags Flags) {
	RELIB_ASSERT(config.contains(pConfigName));
	this->pLabel = pLabel;
	this->Type = Type;
	this->pValue = Type == ImGuiDataType_U64 ? (void*)&std::get<uint64_t>(config[pConfigName]) : (void*)&std::get<int>(config[pConfigName]);
	this->pDescription = pDescription;
	this->pStep = pStep;
	this->pStepFast = pStepFast;
	this->pFormat = pFormat;
	this->Flags = Flags;
}

void InputScalar::Render() {
	RenderWidgetContainer();
	RenderDescription();
	ImGui::PushItemWidth(fGuiScale * 200);
	ImGui::InputScalar(pLabel, Type, pValue, pStep, pStepFast, pFormat, Flags);
	EndWidgetRender();
}