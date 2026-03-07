/*!
 * @file gui.cpp
 * @author undisassemble
 * @brief GUI functions
 * @version 0.0.0
 * @date 2026-03-06
 * @copyright MIT License
 * 
 * @todo Feature search
 */

#include "imgui.h"
#include "util.hpp"
#include <sal.h>
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

// Globals
bool bMinimized = false, bOpen = true, bInitialized = false;
int iGuiWidth = 850;
int iGuiHeight = 560;
float fGuiScale = 1.f;
ImGuiWindow* pImGuiWindow = NULL;
extern Asm* pAssembly;
const ImWchar range[] = { 0xE005, 0xF8FF, 0 };
RELEASE_ONLY(const) ImVec4 fBgColTopLeft = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
RELEASE_ONLY(const) ImVec4 fBgColTopRight = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
RELEASE_ONLY(const) ImVec4 fBgColBotLeft = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
RELEASE_ONLY(const) ImVec4 fBgColBotRight = ImVec4(25.f / 255.f, 25.f / 255.f, 25.f / 255.f, 1.f);
uint8_t u8CurrentCategory = 0;
struct {
	char* pTitle = NULL;
	char* pText = NULL;
	UINT uType = 0;
} CurrentModal;

#define IMGUI_TOGGLE(str, var) { bool _TEMP_BOOL = var; if(ImGui::Checkbox(str, &_TEMP_BOOL)) { var = _TEMP_BOOL; } } // Allows ImGui::Checkbox to be used with bitfields


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

void DebugWarning() {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(227, 185, 104, 255));
	ImGui::Text(ICON_BUG);
	ImGui::PopStyleColor();
	ImGui::SetItemTooltip("This feature is experimental, use with caution!");
}

void FeatureWarning(_In_ char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(227, 185, 104, 255));
	ImGui::Text(ICON_TRIANGLE_EXCLAMATION);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip("%s", text);
}

void FeatureInfo(_In_ char* text = NULL) {
	ImGui::SameLine();
	ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(152, 205, 253, 255));
	ImGui::Text(ICON_CIRCLE_INFO);
	ImGui::PopStyleColor();
	if (text) ImGui::SetItemTooltip("%s", text);
}

void DrawGUI() {
	// Dont do anything if window is not shown
	if (!bOpen || bMinimized) return;
	
	ImGui::Begin("Yet Another Packer", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoTitleBar);
	ImGui::GetBackgroundDrawList()->AddRectFilledMultiColor(ImVec2(0, 0), ImVec2(iGuiWidth, iGuiHeight), ImGui::GetColorU32(fBgColTopLeft), ImGui::GetColorU32(fBgColTopRight), ImGui::GetColorU32(fBgColBotRight), ImGui::GetColorU32(fBgColBotLeft));

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
		if (ImGui::BeginMenu("About")) {
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open Website")) { ShellExecuteA(Data.hWnd, "open", "https://undisassemble.dev/yap", NULL, NULL, 0); }
			if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/LICENSE", NULL, NULL, 0); }
			ImGui::EndMenu();
		}
		//ImGui::SetCursorPos(ImVec2((width - ImGui::CalcTextSize("Yet Another Packer").x) / 2, 0));
		//ImGui::Text("Yet Another Packer");
		if (ImGui::CollapseButton(ImGui::GetCurrentWindow()->GetID("#COLLAPSE"), ImVec2(iGuiWidth - 48 * fGuiScale, 3))) { ImGui::GetCurrentWindow()->Collapsed = !ImGui::GetCurrentWindow()->Collapsed; }
		if (ImGui::CloseButton(ImGui::GetCurrentWindow()->GetID("#CLOSE"), ImVec2(iGuiWidth - 26 * fGuiScale, 3))) { bOpen = false; }
		ImGui::EndMenuBar();
	}
	
	// Configuration menu
	if (!Data.bRunning) {
		// Category selection
		const char* categories[] = {
			ICON_BOX_ARCHIVE " Packing",
			ICON_CODE " Reassembly",
			ICON_GEARS " Advanced",
			DEBUG_ONLY(ICON_BUG " Debug")
		};
		const float fBtnWidth = ((float)iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2 - ImGui::GetStyle().ItemSpacing.x * (countof(categories) - 1)) / (countof(categories));
		ImGui::PushFont(NULL, ImGui::GetFontSize() * 1.25);
		for (int i = 0; i < countof(categories); i++) {
			ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(u8CurrentCategory == i ? ImGuiCol_ButtonActive : ImGuiCol_Button));
			ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::GetStyleColorVec4(u8CurrentCategory == i ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered));
			if (ImGui::Button(categories[i], ImVec2(fBtnWidth, 50))) u8CurrentCategory = i;
			ImGui::PopStyleColor(2);
			ImGui::SameLine();
		}
		ImGui::PopFont();
		ImGui::NewLine();

		// Category contents
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y);
		ImGui::BeginChild("#TabContents", ImVec2(iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2, iGuiHeight - ImGui::GetStyle().WindowPadding.y - ImGui::GetCursorPosY()));
		
		if (u8CurrentCategory == 0) { // Packing
			
		}

		else if (u8CurrentCategory == 1) { // Reassembly

		}

		else if (u8CurrentCategory == 2) { // Advanced

		}

		else {
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

void GLFWErrorHandler(int error, const char* message) {
	LOG(Failed, MODULE_YAP, "GLFW error %d: %s\n", error, message);
}

bool BeginGUI() {
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
	io.Fonts->AddFontFromMemoryCompressedTTF(icons_compressed_data, icons_compressed_size, 16 * fGuiScale, &config, range);

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