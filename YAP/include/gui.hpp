/*!
 * @file gui.hpp
 * @author undisassemble
 * @brief GUI definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#pragma once

#include "util.hpp"
#include <imgui.h>
#include <imgui_internal.h>

/*!
 * @brief Starts the UI.
 * 
 * @retval true Success.
 * @retval false Failure.
 */
bool BeginGUI();

/*!
 * @brief Applies the ImGui theme set in `Settings.Theme`.
 */
void ApplyImGuiTheme();

/*!
 * @brief Opens the file selection menu.
 * 
 * @param [out] pOut Buffer to store file path to.
 * @param [in] szOut Size of the `pOut` buffer.
 * @param [in] pFilter File type filter. Check `lpstrFilter` in https://learn.microsoft.com/en-us/windows/win32/api/commdlg/ns-commdlg-openfilenamea.
 * @param [out] pFileNameOffset Pointer to receive offset of the beginning of the file name (optional).
 * @param [in] bSaveTo Opened dialogue is a 'save file' dialogue instead of 'load file'.
 * @retval true Success.
 * @retval false Failure.
 */
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo);