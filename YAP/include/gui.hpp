/*!
 * @file gui.hpp
 * @author undisassemble
 * @brief GUI definitions
 * @version 0.0.0
 * @date 2026-03-16
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
            Base* pNextPeer = NULL;
            Base* pChildren = NULL;
            const char* pLabel = NULL;
            const char* pDescription = NULL;
            uint8_t u8Flags = 0;
            const char* pFlagText = NULL;
        
        public:
            inline Base* GetNextWidget() { return pNextPeer; }
            inline Base* GetChildren() { return pChildren; }
            inline void DebugWarning() { u8Flags |= WIDGET_DEBUG; }
            inline void FeatureWarning(_In_ const char* pText) { u8Flags |= WIDGET_WARNING; pFlagText = pText; }
            inline void FeatureInfo(_In_ const char* pText) { u8Flags |= WIDGET_INFO; pFlagText = pText; }
            inline void SetIsChild() { u8Flags |= WIDGET_IS_CHILD; }
            inline void RemoveNextWidget() { if (pNextPeer) pNextPeer = pNextPeer->GetNextWidget(); }
            
            inline void SetNextWidget(_In_ Base* pWidget) {
                Base* pOld = pNextPeer;
                pNextPeer = pWidget;
                if (pOld) pNextPeer->SetNextWidget(pOld);
            }

            void AddNextWidget(_In_ Base* pWidget);
            void AddChild(_In_ Base* pWidget);

            void RenderWidgetContainer(_In_ int iHeight = -1);
            void RenderDescription();
            virtual void Render() = 0;
            void EndWidgetRender();
        };

        class Checkbox : public Base {
        private:
            bool* pValue = NULL;
        
        public:
            Checkbox(_In_ const char* pLabel, _In_ const char* pConfigName, _In_ const char* pDescription = NULL);

            void Render() override;
        };
    };

    /*!
     * @brief The structure of pages/widgets displayed in the UI.
     * @details Vector of pages, each with a name and elements. Populated by GUI::Setup, which should be called before adding any custom elements. Look at GUI::Setup to see page indexes and how contents are formatted.
     * @see GUI::Setup
     */
    extern std::vector<std::pair<const char*, WidgetClasses::Base*>> Widgets;
};