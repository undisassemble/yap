#pragma once

#include "util.hpp"
#include <imgui/imgui.h>
#include <imgui/imgui_internal.h>

bool BeginGUI();
void ApplyImGuiTheme();
bool LoadProject();
bool SaveProject();
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo);
void SaveSettings();
void LoadSettings();