#pragma once

#include <stdint.h>
#include <Windows.h>
#include <imgui.h>
#include <imgui_internal.h>

void InitGUI();
bool BeginGUI();
void ApplyImGuiTheme();
bool LoadProject();
bool SaveProject();
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo);
void SaveSettings();
void LoadSettings();