/*!
 * @file gui.hpp
 * @author undisassemble
 * @brief GUI definitions
 * @version 0.0.0
 * @date 2026-03-23
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
#define WIDGET_IS_CHILD 8
#define WIDGET_SHOW_CHILDREN 16
#define WIDGET_DISABLED_CHILDREN 32

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

    namespace WidgetClasses {
        /*!
         * @brief Base class for any widgets.
         */
        class Base {
        protected:
            Base* pChild = NULL;
            const char* pLabel = NULL;
            const char* pDescription = NULL;
            uint8_t u8Flags = 0;
            const char* pFlagText = NULL;
        
        public:
            inline Base* GetChild() { return pChild; }
            inline Base* DebugWarning() { u8Flags |= WIDGET_DEBUG; return this; }
            inline Base* FeatureWarning(_In_ const char* pText) { u8Flags |= WIDGET_WARNING; pFlagText = pText; return this; }
            inline Base* FeatureInfo(_In_ const char* pText) { u8Flags |= WIDGET_INFO; pFlagText = pText; return this; }
            inline void SetIsChild() { u8Flags |= WIDGET_IS_CHILD; }
            inline bool ShouldShowChildren() { return u8Flags & WIDGET_SHOW_CHILDREN; }
            inline bool AreChildrenDisabled() { return u8Flags & WIDGET_DISABLED_CHILDREN; }

            void AddChild(_In_ Base* pWidget);
            Base* WithChildren(_In_ uint32_t u8NumChildren, ...);

            void RenderWidgetContainer(_In_ int iHeight = -1);
            void RenderDescription();
            virtual void Render() = 0;
            void EndWidgetRender();
        };

        class Category : public Base {
        public:
            Category(_In_ const char* pLabel, _In_ const char* pDescription = NULL, _In_ bool bStartOpen = false);
            void Render() override;
        };

        class Checkbox : public Base {
        private:
            bool* pValue = NULL;
        
        public:
            Checkbox(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pDescription = NULL);
            void Render() override;
        };

        class Slider : public Base {
        private:
            int* pValue = NULL;
            int nMin = 0;
            int nMax = 0;
            const char* pFormat = NULL;

        public:
            Slider(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ int nMin, _In_ int nMax, _In_ const char* pDescription = NULL, _In_ const char* pFormat = "%d");
            void Render() override;
        };

        class Dropdown : public Base {
        private:
            int* pValue = NULL;
            const char* pItems = NULL;
        
        public:
            Dropdown(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pItems, _In_ const char* pDescription = NULL);
            void Render() override;
        };

        class InputText : public Base {
        private:
            Buffer* pBuf = NULL;
            ImGuiInputTextFlags Flags = 0;

        public:
            InputText(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pDescription = NULL, _In_ ImGuiInputTextFlags Flags = 0);
            void Render() override;
        };

        class InputScalar : public Base {
        private:
            ImGuiDataType Type = 0;
            void* pValue = NULL;
            void* pStep = NULL;
            void* pStepFast = NULL;
            const char* pFormat = NULL;
            ImGuiInputTextFlags Flags = 0;
        
        public:
            InputScalar(_In_ const char* pLabel, _In_ ImGuiDataType Type, _In_ const char* pConfigName, _In_ const char* pDescription = NULL, _In_ void* pStep = NULL, _In_ void* pStepFast = NULL, _In_ const char* pFormat = NULL, _In_ ImGuiInputTextFlags Flags = 0);
            void Render() override;
        };
    };

    /*!
     * @brief The structure of pages/widgets displayed in the UI.
     * @details Vector of pages, each with a name and elements. Populated by GUI::Setup, which should be called before adding any custom elements. Look at GUI::Setup to see page indexes and how contents are formatted.
     * @see GUI::Setup
     */
    extern std::vector<std::pair<const char*, std::vector<WidgetClasses::Base*>>> Widgets;
};