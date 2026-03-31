/*!
 * @file gui.cpp
 * @author undisassemble
 * @brief GUI functions
 * @version 0.0.0
 * @date 2026-03-31
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

// Globals
bool bMinimized = false, bOpen = true, bInitialized = false;
int iGuiWidth = 850;
int iGuiHeight = 560;
float fGuiScale = 1.f;
ImGuiWindow* pImGuiWindow = NULL;
extern Asm* pAssembly;
ImVec4 fBgColTopLeft, fBgColTopRight, fBgColBotLeft, fBgColBotRight;
float fRadius, fR = 0, fG = std::numbers::pi * 2.f / 3.f, fB = fG * 2.f;
uint8_t u8CurrentCategory = 0;
Buffer VersionString;
struct {
	char* pTitle = NULL;
	char* pText = NULL;
	UINT uType = 0;
} CurrentModal;

using namespace GUI;

std::vector<std::pair<const char*, std::vector<WidgetClasses::Base*>>> GUI::Widgets;

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
	bool bRet = bSaveTo ? GetSaveFileName(&FileName) : GetOpenFileName(&FileName);

	// Return
	if (pFileNameOffset && bRet) {
		*pFileNameOffset = FileName.nFileOffset;
	}
	return bRet;
}

bool ToolbarDropdown(_In_ const char* pName, _In_ float fTextHeight, _In_ const char* pId = NULL) {
	bool bRet = false;
	ImVec2 pos = ImGui::GetCursorScreenPos();
	ImVec2 size = ImVec2(ImGui::CalcTextSize(pName).x + fTextHeight * 2, 25 * fGuiScale); // fTextHeight being used instead of FramePadding to keep consistency with top/bottom padding
	ImGui::SetCursorScreenPos(pos);
	if ((bRet = ImGui::InvisibleButton(pId ? pId : pName, size))) {
		ImGui::GetForegroundDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBgActive));
	} else if (ImGui::IsItemHovered()) {
		ImGui::GetForegroundDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(ImGuiCol_FrameBgHovered));
	}
	ImGui::GetForegroundDrawList()->AddText(ImVec2(pos.x + fTextHeight, fTextHeight), ImGui::GetColorU32(ImGuiCol_Text), pName);
	ImGui::SetCursorScreenPos(ImVec2(pos.x + size.x, pos.y));
	return bRet;
}

void UpdateBackground() {
	float fRadians = std::numbers::pi * (float)std::get<int>(settings["Style.iGradientAngle"]) / 180.f;
	ImVec2 ColorPosition = ImVec2(std::cos(fRadians) * fRadius, std::sin(fRadians) * fRadius);
	ColorPosition.x += iGuiWidth / 2.f;
	ColorPosition.y += iGuiHeight / 2.f;

	std::vector<std::pair<ImVec2, ImVec4&>> items = {
		{ ImVec2(0, 0), fBgColTopLeft },
		{ ImVec2(iGuiWidth, 0), fBgColTopRight },
		{ ImVec2(0, iGuiHeight), fBgColBotLeft },
		{ ImVec2(iGuiWidth, iGuiHeight), fBgColBotRight }
	};
	for (std::pair<ImVec2, ImVec4&> item : items) {
		float dist = sqrt(pow(item.first.x - ColorPosition.x, 2) + pow(item.first.y - ColorPosition.y, 2));
		float fIntensity = std::get<int>(settings["Style.Accent.iIntensity"]) * (fRadius * 2 - dist) / (fRadius * 200);
		item.second.x = fIntensity * std::get<int>(settings["Style.Accent.iR"]) / 255.f;
		item.second.y = fIntensity * std::get<int>(settings["Style.Accent.iG"]) / 255.f;
		item.second.z = fIntensity * std::get<int>(settings["Style.Accent.iB"]) / 255.f;
		item.second.w = 1.f;
	}

	ImGui::GetStyle().Colors[ImGuiCol_SliderGrab] = ImGui::GetStyle().Colors[ImGuiCol_SliderGrabActive] = ImGui::GetStyle().Colors[ImGuiCol_CheckMark] = ImColor(std::get<int>(settings["Style.Accent.iR"]), std::get<int>(settings["Style.Accent.iG"]), std::get<int>(settings["Style.Accent.iB"]), 180);
	ImGui::GetStyle().Colors[ImGuiCol_SliderGrabActive].w = 1.f;
}

void DrawGUI() {
	// Dont do anything if window is not shown
	if (!bOpen || bMinimized) return;

	// Party mode
	if (std::get<bool>(settings["Style.bPartyMode"])) {
		ImVec2 r = ImVec2(std::cos(fR) * fRadius, std::sin(fR) * fRadius);
		ImVec2 g = ImVec2(std::cos(fG) * fRadius, std::sin(fG) * fRadius);
		ImVec2 b = ImVec2(std::cos(fB) * fRadius, std::sin(fB) * fRadius);
		fR = (fR + std::numbers::pi / 180.f);
		while (fR > 2 * std::numbers::pi) fR -= 2 * std::numbers::pi;
		fG = (fG + std::numbers::pi / 180.f);
		while (fG > 2 * std::numbers::pi) fG -= 2 * std::numbers::pi;
		fB = (fB + std::numbers::pi / 180.f);
		while (fB > 2 * std::numbers::pi) fB -= 2 * std::numbers::pi;

		r = ImVec2(r.x + iGuiWidth / 2.f, r.y + iGuiHeight / 2.f);
		g = ImVec2(g.x + iGuiWidth / 2.f, g.y + iGuiHeight / 2.f);
		b = ImVec2(b.x + iGuiWidth / 2.f, b.y + iGuiHeight / 2.f);

		std::vector<std::pair<ImVec2, ImVec4&>> items = {
			{ ImVec2(0, 0), fBgColTopLeft },
			{ ImVec2(iGuiWidth, 0), fBgColTopRight },
			{ ImVec2(0, iGuiHeight), fBgColBotLeft },
			{ ImVec2(iGuiWidth, iGuiHeight), fBgColBotRight }
		};
		for (std::pair<ImVec2, ImVec4&> item : items) {
			float dist = sqrt(pow(item.first.x - r.x, 2) + pow(item.first.y - r.y, 2));
			item.second.x = std::get<int>(settings["Style.Accent.iIntensity"]) * (fRadius * 2 - dist) / (fRadius * 200);
			dist = sqrt(pow(item.first.x - g.x, 2) + pow(item.first.y - g.y, 2));
			item.second.y = std::get<int>(settings["Style.Accent.iIntensity"]) * (fRadius * 2 - dist) / (fRadius * 200);
			dist = sqrt(pow(item.first.x - b.x, 2) + pow(item.first.y - b.y, 2));
			item.second.z = std::get<int>(settings["Style.Accent.iIntensity"]) * (fRadius * 2 - dist) / (fRadius * 200);
		}
	}
	
	ImGui::Begin("Yet Another Packer", &bOpen, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
	ImGui::GetBackgroundDrawList()->AddRectFilledMultiColor(ImVec2(0, 0), ImVec2(iGuiWidth, iGuiHeight), ImGui::GetColorU32(fBgColTopLeft), ImGui::GetColorU32(fBgColTopRight), ImGui::GetColorU32(fBgColBotRight), ImGui::GetColorU32(fBgColBotLeft));

	// Menu bar + title
	float fMenuBarHeight = 25 * fGuiScale, fTextHeight = (fMenuBarHeight - ImGui::GetTextLineHeight()) / 2;
	ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(ImGui::GetWindowWidth(), fMenuBarHeight), ImGui::GetColorU32(ImGuiCol_MenuBarBg));
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetStyle().WindowPadding.x, fTextHeight), ImGui::GetColorU32(ImGuiCol_Text), "Yet Another Packer   |");
	
	// File button
	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetStyle().WindowPadding.x + ImGui::CalcTextSize("Yet Another Packer   |  ").x, 0));
	ImVec2 PopupPos = ImVec2(ImGui::GetCursorScreenPos().x, fMenuBarHeight);
	if (ToolbarDropdown("File", fTextHeight, "FileBtn")) ImGui::OpenPopup("FilePopup");
	if (ImGui::BeginPopup("FilePopup")) {
		ImGui::SetWindowPos(PopupPos, ImGuiCond_Always);
		if (ImGui::MenuItem(ICON_FILE " New", "Ctrl + N")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveConfig(); }
 		if (ImGui::MenuItem(ICON_FOLDER_OPEN " Open", "Ctrl + O")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, false); LoadConfig(); }
		ImGui::BeginDisabled(!Data.ConfigPath[0]);
 		if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save", "Ctrl + S")) { SaveConfig(); }
 		ImGui::EndDisabled();
 		if (ImGui::MenuItem(ICON_FLOPPY_DISK " Save as", "Ctrl + Shift + S")) { OpenFileDialogue(Data.ConfigPath, sizeof(Data.ConfigPath), "YAP Project\0*.yaproj\0All Files\0*.*\0", NULL, true); SaveConfig(); }
		ImGui::EndPopup();
	}

	// Settings button
	PopupPos = ImVec2(ImGui::GetCursorScreenPos().x, fMenuBarHeight);
	if (ToolbarDropdown("Settings", fTextHeight, "SettingsBtn")) ImGui::OpenPopup("SettingsPopup");
	if (ImGui::BeginPopup("SettingsPopup")) {
		ImGui::SetWindowPos(PopupPos, ImGuiCond_Always);
		if (ImGui::BeginMenu("Style")) {
			if (ImGui::SliderInt("Gradient Angle", &std::get<int>(settings["Style.iGradientAngle"]), 0, 359)) UpdateBackground();
			if (ImGui::SliderInt("Intensity", &std::get<int>(settings["Style.Accent.iIntensity"]), 0, 100)) UpdateBackground();
			if (ImGui::SliderInt("R", &std::get<int>(settings["Style.Accent.iR"]), 0, 255)) UpdateBackground();
			if (ImGui::SliderInt("G", &std::get<int>(settings["Style.Accent.iG"]), 0, 255)) UpdateBackground();
			if (ImGui::SliderInt("B", &std::get<int>(settings["Style.Accent.iB"]), 0, 255)) UpdateBackground();
			ImGui::Separator();
			if (ImGui::BeginMenu("Presets")) {
				std::vector<std::pair<const char*, ImVec4>> presets = {
					{ "Lavender", ImVec4(88, 46, 122, 0) },
					{ "Blue", ImVec4(20, 113, 167, 0) },
					{ "Cyan", ImVec4(57, 162, 172, 0) },
					{ "Green", ImVec4(45, 148, 82, 0) },
					{ "Yellow", ImVec4(148, 158, 41, 0) },
					{ "Orange", ImVec4(143, 93, 7, 0) },
					{ "Red", ImVec4(146, 36, 36, 0) },
					{ "Pink", ImVec4(126, 52, 116, 0) },
				};
				for (std::pair<const char*, ImVec4> preset : presets) {
					if (ImGui::MenuItem(preset.first)) {
						settings["Style.Accent.iR"] = (int)preset.second.x;
						settings["Style.Accent.iG"] = (int)preset.second.y;
						settings["Style.Accent.iB"] = (int)preset.second.z;
						UpdateBackground();
					}
				}
				if (ImGui::MenuItem("Party Mode", NULL, &std::get<bool>(settings["Style.bPartyMode"]))) UpdateBackground();
				ImGui::EndMenu();
			}
			ImGui::EndMenu();
		}
		ImGui::EndPopup();
	}

	// About button
	PopupPos = ImVec2(ImGui::GetCursorScreenPos().x, fMenuBarHeight);
	if (ToolbarDropdown("About", fTextHeight, "AboutBtn")) ImGui::OpenPopup("AboutPopup");
	if (ImGui::BeginPopup("AboutPopup")) {
		ImGui::SetWindowPos(PopupPos, ImGuiCond_Always);
		if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open GitHub")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap", NULL, NULL, 0); }
		if (ImGui::MenuItem(ICON_CIRCLE_INFO " Open Website")) { ShellExecuteA(Data.hWnd, "open", "https://undisassemble.dev/yap", NULL, NULL, 0); }
		if (ImGui::MenuItem(ICON_CIRCLE_INFO " License")) { ShellExecuteA(Data.hWnd, "open", "https://github.com/undisassemble/yap/blob/main/LICENSE", NULL, NULL, 0); }
		if (ImGui::MenuItem(ICON_CIRCLE_INFO " Version")) { Modal((char*)VersionString.Data(), ICON_CIRCLE_INFO " Version", MB_OK); }
		ImGui::EndPopup();
	}

	// Close button
	float fBtnWidth = 40 * fGuiScale;
	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowWidth() - fBtnWidth, 0));
	if (ImGui::InvisibleButton("WindowClose", ImVec2(fBtnWidth, fMenuBarHeight))) {
		bOpen = false;
	} else if (ImGui::IsItemHovered()) {
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(ImGui::GetWindowWidth() - fBtnWidth, 0), ImVec2(ImGui::GetWindowWidth(), fMenuBarHeight), ImGui::GetColorU32(ImVec4(188, 0, 0, 255)));
	}
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetWindowWidth() - fBtnWidth + (fBtnWidth - ImGui::CalcTextSize(ICON_WINDOW_CLOSE).x) / 2, fGuiScale + fTextHeight), ImGui::GetColorU32(ImGuiCol_Text), ICON_WINDOW_CLOSE);
	
	// Minimize button
	ImGui::SetCursorScreenPos(ImVec2(ImGui::GetWindowWidth() - fBtnWidth * 2, 0));
	if (ImGui::InvisibleButton("WindowMinimize", ImVec2(fBtnWidth, fMenuBarHeight))) {
		ImGui::GetCurrentWindow()->Collapsed = true;
	} else if (ImGui::IsItemHovered()) {
		ImGui::GetForegroundDrawList()->AddRectFilled(ImVec2(ImGui::GetWindowWidth() - fBtnWidth * 2, 0), ImVec2(ImGui::GetWindowWidth() - fBtnWidth, fMenuBarHeight), ImGui::GetColorU32(ImVec4(0.7f, 0.7f, 0.7f, 0.2f)));
	}
	ImGui::GetForegroundDrawList()->AddText(ImVec2(ImGui::GetWindowWidth() - fBtnWidth * 2 + (fBtnWidth - ImGui::CalcTextSize(ICON_WINDOW_MINIMIZE).x) / 2, fGuiScale + fTextHeight), ImGui::GetColorU32(ImGuiCol_Text), ICON_WINDOW_MINIMIZE);

	ImGui::SetCursorPosY(fMenuBarHeight + ImGui::GetStyle().WindowPadding.y);
	
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

		if (u8CurrentCategory < Widgets.size()) {
			WidgetClasses::Base *pChild;
			for (WidgetClasses::Base* pItem : Widgets[u8CurrentCategory].second) {
				pItem->Render();
				if (pItem->ShouldShowChildren()) {
					ImGui::BeginDisabled(pItem->AreChildrenDisabled());
					pChild = pItem;
					while ((pChild = pChild->GetChild())) {
						pChild->Render();
					}
					ImGui::EndDisabled();
				}
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
	style.Colors[ImGuiCol_WindowBg] = ImColor(0, 0, 0, 0);
	style.Colors[ImGuiCol_PopupBg] = ImColor(35, 35, 35, 240);
	style.Colors[ImGuiCol_FrameBg] = ImColor(20, 20, 20, 180);
    style.Colors[ImGuiCol_FrameBgHovered] = ImColor(25, 25, 25, 180);
    style.Colors[ImGuiCol_FrameBgActive] = ImColor(30, 30, 30, 180);
	style.Colors[ImGuiCol_MenuBarBg] = ImColor(40, 40, 40, 220);
	style.Colors[ImGuiCol_ScrollbarBg] = ImColor(0, 0, 0, 0);
	style.Colors[ImGuiCol_ScrollbarGrab] = ImColor(75, 75, 75, 255);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImColor(130, 130, 130, 255);
    style.Colors[ImGuiCol_CheckMark] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_SliderGrab] = ImColor(75, 75, 75, 255);
    style.Colors[ImGuiCol_SliderGrabActive] = ImColor(100, 100, 100, 255);
    style.Colors[ImGuiCol_Button] = ImColor(40, 40, 40, 220);
    style.Colors[ImGuiCol_ButtonHovered] = ImColor(60, 60, 60, 220);
    style.Colors[ImGuiCol_ButtonActive] = ImColor(80, 80, 80, 220);
    style.Colors[ImGuiCol_Header] = ImColor(40, 40, 40, 220);
    style.Colors[ImGuiCol_HeaderHovered] = ImColor(60, 60, 60, 220);
    style.Colors[ImGuiCol_HeaderActive] = ImColor(80, 80, 80, 220);
	style.WindowRounding = 0.f;
	style.WindowBorderSize = 0.f;
	style.FrameRounding = 5.f;
	style.GrabMinSize = 10.f;
	style.GrabRounding = 5.f;
	style.PopupRounding = 5.f;

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
	fRadius = sqrt(iGuiWidth * iGuiWidth + iGuiHeight * iGuiHeight);
	UpdateBackground();

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

	// Set version string
	VersionString.Allocate(2048);
	snprintf(
		(char*)VersionString.Data(),
		VersionString.Size(),
		"YAP: " __YAP_VERSION__
		"\nReLib: " __RELIB_VERSION__
		"\nLZMA: 24.07"
		"\nImGui: " IMGUI_VERSION
		"\nZydis: %lld.%lld.%lld"
		"\nZycore: %lld.%lld.%lld" 
		"\nAsmJit: %d.%d.%d"
		"\nGLFW: %s"
		"\nOpenGL: %s"
		"\nBuild: " __YAP_BUILD__
		"\nTime: " __DATE__ " @ " __TIME__,
		ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION),
		ZYCORE_VERSION_MAJOR(ZYCORE_VERSION), ZYCORE_VERSION_MINOR(ZYCORE_VERSION), ZYCORE_VERSION_PATCH(ZYCORE_VERSION),
		ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION),
		glfwGetVersionString(),
		glGetString(GL_VERSION)
	);
	VersionString.Allocate(strlen((char*)VersionString.Data()) + 1);

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

	int64_t i64DiffInstruction = (int64_t)sizeof(DecodedInstruction) - sizeof(ZydisDecodedInstruction);
	float fPctDiffInstruction = (100.f * i64DiffInstruction) / (int64_t)sizeof(ZydisDecodedInstruction);
	
	int64_t i64DiffOperand = (int64_t)sizeof(DecodedOperand) - sizeof(ZydisDecodedOperand);
	float fPctDiffOperand = (100.f * i64DiffOperand) / (int64_t)sizeof(ZydisDecodedOperand);
	
	int64_t i64TotalDiff = i64DiffOperand * 4 + i64DiffInstruction;
	float fPctDiffTotal = (100.f * i64TotalDiff) / (int64_t)(sizeof(Line) - i64TotalDiff);

	Widgets = {
		{
			ICON_BOX_ARCHIVE " Packing",
			{
				(new Checkbox("Enable Packer", "Packing.bEnabled", "Wraps the original binary with a custom loader"))->WithChildren(
					1,
					new Checkbox("Don't pack resources", "Packing.bDontCompressRsrc", "Preserves everything in the resource directory, keeping details such as icons and privileges")
				),
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
			}
		},
		{
			ICON_CODE " Reassembly",
			{
				new Checkbox("Enable Reassembler", "Reassembly.bEnabled", "Disassembles your application, and assembles a new modified version"),
				new Slider("Mutation level", "Reassembly.iMutationLevel", 0, 5, "How much garbage code should be inserted between real code (slow)"),
				new Checkbox("Instruction substitution", "Reassembly.bSubstitution", "Replaces some existing instructions with other, more complicated alternatives"),
				new Checkbox("Remove useless data", "Reassembly.bRemoveData", "Removes some data from the PE headers"),
				new Checkbox("Strip debug symbols", "Reassembly.bStrip", "Remove debugging information from the PE"),
				new Checkbox("Strip DOS stub", "Reassembly.bStripDOSStub", "Remove DOS stub from the PE")
			}
		},
		{
			ICON_GEARS " Advanced",
			{
				(new Category("Packer"))->WithChildren(
					7,
					new Checkbox("Fake symbol table", "Advanced.bFakeSymbols"),
					(new Checkbox("Mutate", "Advanced.bMutateAssembly"))->FeatureWarning("Disabling will make unpacking easier"),
					(new Checkbox("Substitute", "Advanced.bEnableSubstitution"))->FeatureWarning("Disabling will make unpacking easier"),
					new Checkbox("Semi-random section names", "Advanced.bSemiRandomSecNames"),
					new Checkbox("Full-random section names", "Advanced.bTrueRandomSecNames"),
					new InputText("Section 1 name", "Advanced.sSec1Name"),
					new InputText("Section 2 name", "Advanced.sSec2Name")
				),
				(new Category("Reassembler"))->WithChildren(
					1,
					new InputScalar("Rebase image", ImGuiDataType_U64, "Advanced.u64Rebase", "Changes images prefered base address (0 to disable)", NULL, NULL, "%p", ImGuiInputTextFlags_CharsHexadecimal)
				)
			}
		},
#ifdef _DEBUG
		{
			ICON_BUG " Debug",
			{
				new Checkbox("Dump disassembly", "Debug.bDumpAsm"),
				new Checkbox("Dump raw sections", "Debug.bDumpSections"),
				new Checkbox("Dump function ranges", "Debug.bDumpFunctions"),
				new Checkbox("Generate breakpoints", "Debug.bGenerateBreakpoints"),
				new Checkbox("Generate NOP markings", "Debug.bGenerateMarks"),
				new Checkbox("Disable relocations", "Debug.bDisableRelocations"),
				new Checkbox("Strict mutation", "Debug.bStrictMutation"),
				new Checkbox("Skip disassembly validation", "Debug.bSkipDisasmValidation"),
				new Text("DecodedInstruction reduction: %lld bytes (%.2f%%)\nDecodedOperand reduction: %lld bytes (%.2f%%)\nTotal memory reduction (per line): %lld bytes (%.2f%%)", i64DiffInstruction, fPctDiffInstruction, i64DiffOperand, fPctDiffOperand, i64TotalDiff, fPctDiffTotal)
			}
		}
#endif
	};
}





/***** WIDGETS ******/

using namespace WidgetClasses;

#define GetScrollbarSpace() (ImGui::GetScrollMaxY() > 0.f ? ImGui::GetStyle().WindowPadding.x + ImGui::GetCurrentWindow()->ScrollbarSizes[0] : 0)

void Base::AddChild(_In_ Base* pWidget) {
	pWidget->SetIsChild();
	if (!pChild) {
		pChild = pWidget;
		return;
	}
	Base* pParent = pChild;
	while (pParent->GetChild()) {
		pParent = pParent->GetChild();
	}
	pChild->AddChild(pWidget);
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
				Base* p = this;
				while ((p = p->GetChild())) {
					nChildren++;
				}
			}
			iHeight = ImGui::GetFrameHeight() * nChildren + ImGui::GetStyle().ItemSpacing.y * (nChildren - 1) + ImGui::GetStyle().FramePadding.y * 2;
			if (nChildren > 1 && u8Flags & WIDGET_SHOW_CHILDREN) {
				iHeight += ImGui::GetStyle().ItemSpacing.y + 1;
			}
		}

		ImVec2 tl = ImVec2(ImGui::GetStyle().WindowPadding.x, ImGui::GetCursorScreenPos().y);
		ImVec2 br = ImVec2(iGuiWidth - tl.x - GetScrollbarSpace(), tl.y + iHeight);
		ImGui::GetWindowDrawList()->AddRectFilled(tl, br, ImGui::GetColorU32(ImGuiCol_Button), ImGui::GetStyle().FrameRounding);

		// Dropdown button
		if (pChild) {
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
				ImGui::GetWindowDrawList()->AddRectFilled(tl, ImVec2(tl.x + fButtonSize, tl.y + fButtonSize), ImGui::GetColorU32(ImGui::IsMouseDown(ImGuiMouseButton_Left) ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered), ImGui::GetStyle().FrameRounding, ImDrawFlags_RoundCornersTopLeft | (u8Flags & WIDGET_SHOW_CHILDREN ? 0 : ImDrawFlags_RoundCornersBottomLeft));
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
	if (~u8Flags & WIDGET_IS_CHILD && pChild && u8Flags & WIDGET_SHOW_CHILDREN) {
		ImVec2 l1 = ImVec2(ImGui::GetCursorScreenPos().x, ImGui::GetCursorScreenPos().y);
		ImVec2 l2 = ImVec2(l1.x + iGuiWidth - ImGui::GetStyle().WindowPadding.x * 2 - GetScrollbarSpace(), l1.y + 1);
		ImGui::GetWindowDrawList()->AddRectFilled(l1, l2, ImGui::GetColorU32(ImGuiCol_Separator));
		ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ImGui::GetStyle().ItemSpacing.y + 1);
	} else if ((u8Flags & WIDGET_IS_CHILD) ? !pChild : ~u8Flags & WIDGET_SHOW_CHILDREN) {
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

Text::Text(_In_ char* pText) {
	this->pText = pText;
}

Text::Text(_In_ char* pFormat, _In_ ...) {
	pText = reinterpret_cast<char*>(malloc(2048));
	va_list args;
	va_start(args, pFormat);
	int n = vsnprintf(pText, 2048, pFormat, args);
	va_end(args);
	pText = reinterpret_cast<char*>(realloc(pText, n + 1));
}

void Text::Render() {
	ImVec2 size = ImGui::CalcTextSize(pText);
	RenderWidgetContainer(size.y + ImGui::GetStyle().FramePadding.y * 2);
	ImGui::Text("%s", pText);
	EndWidgetRender();
}