/*!
 * @file gui.hpp
 * @author undisassemble
 * @brief GUI definitions
 * @version 0.0.0
 * @date 2026-03-12
 * @copyright MIT License
 */

#pragma once

#include "util.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <vector>

// Values for u8Flags when creating widgets
#define WIDGET_DEBUG 1
#define WIDGET_WARNING 2
#define WIDGET_INFO 4

namespace GUI {
    /*!
     * @brief Sets up the basic UI elements, should only be used after the initial config is loaded.
     */
    void Setup();

    /*!
     * @brief Starts the UI.
     * 
     * @retval true Success.
     * @retval false Failure.
     */
    bool Begin();

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

    /*!
     * @brief For use in creating custom UI pages/options
     */
    namespace Widgets {

        enum ElementType_t : uint8_t {
        	ElemCheckbox
        };

        struct Element_t {
        	ElementType_t Type;
        	void* pValue;
        	const char* pLabel;
        	const char* pDescription;
        	uint8_t u8Flags;
        	const char* pFlagText = NULL;
        };

        /*!
         * @brief Creates a new checkbox widget, for boolean values.
         * 
         * @param [in] pLabel The label for the widget (short, left hand name)
         * @param [in] pValueName The name for the boolean value stored in `config`
         * @param [in] pDescription Longer description of what it does (right hand text)
         * @param [in] u8Flags Additional flags for the widget, can be WIDGET_DEBUG, WIDGET_WARNING, or WIDGET_INFO
         * @param [in] pFlagText Text that goes along with the icon shown by u8Flags
         * @return Element_t 
         */
        Element_t Checkbox(_In_ const char* pLabel, _In_ const char* pValueName, _In_opt_ const char* pDescription = NULL, _In_opt_ uint8_t u8Flags = 0, _In_opt_ const char* pFlagText = NULL);
    };
};

/*!
 * @brief The structure of pages/widgets displayed in the UI.
 * @details Vector of pages, each with a name and elements. Populated by GUI::Setup, which should be called before adding any custom elements. Look at GUI::Setup to see page indexes and how contents are formatted.
 * @see GUI::Setup
 */
extern std::vector<std::pair<const char*, std::vector<GUI::Widgets::Element_t>>> elements;