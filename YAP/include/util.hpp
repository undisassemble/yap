/*!
 * @file util.hpp
 * @author undisassemble
 * @brief Utility definitions
 * @version 0.0.0
 * @date 2025-05-25
 * @copyright MIT License
 */

#pragma once

// Headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include "version.hpp"
#include "relib/relib.hpp"
#ifndef UTIL_STRUCT_ONLY

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "
#define MODULE_YAP "YAP"
#define MODULE_VM "VM"
#define MODULE_PACKER "Packer"
#define MODULE_REASSEMBLER "ReAsm"
#define MODULE_RELIB "ReLib"

/*!
 * @brief Logging prefixes
 */
enum LoggingLevel_t : int {
	Nothing,      //!< No prefix
	Failed,       //!< [-] prefix
	Success,      //!< [+] prefix
	Warning,      //!< [*] prefix
	Info,         //!< [?] prefix
};

/*!
 * @brief Log information to console and log file.
 * 
 * @param [in] level Prefix.
 * @param [in] mod Module producing the log.
 * @param [in] str Formatted string to log.
 * @param [in] ... Additional information from `str`.
 * @see LoggingLevel_t
 */
void LOG(LoggingLevel_t level, const char* mod, const char* str, ...);

/*!
 * @brief Log information to console and log file.
 * @remark Caller must handle va_start and va_end.
 * 
 * @param [in] level Prefix.
 * @param [in] mod Module producing the log.
 * @param [in] str Formatted string to log.
 * @param [in] vargs Additional information from `str`.
 */
void vLOG(LoggingLevel_t level, const char* mod, const char* str, va_list vargs);

// Macros
#define IMGUI_TOGGLE(str, var) { bool _TEMP_BOOL = var; if(ImGui::Checkbox(str, &_TEMP_BOOL)) { var = _TEMP_BOOL; } } // Allows ImGui::Checkbox to be used with bitfields
#define ASMJIT_LIBRARY_VERSION_MAJOR(version) ((version & 0xFF0000) >> 16)
#define ASMJIT_LIBRARY_VERSION_MINOR(version) ((version & 0xFF00) >> 8)
#define ASMJIT_LIBRARY_VERSION_PATCH(version) (version & 0xFF)
#define countof(x) (sizeof(x) / sizeof(*x))

const int VMMinimumSize = 21;

enum PackerTypes_t : int {
	YAP,
	Themida,
	WinLicense,
	UPX,
	MPRESS,
	Enigma,
	ExeStealth
};

enum State_t : BYTE {
	Idle,
	Packing,
	Disassembling,
	Assembling
};
#endif // UTIL_STRUCT_ONLY

struct Data_t {
	char Project[MAX_PATH] = { 0 };
	char SaveFileName[MAX_PATH] = { 0 };
	float fTotalProgress = 0.f;
	float fTaskProgress = 0.f;
	char* sTask = NULL;
	State_t State = Idle;
	uint64_t Reserved = 0;
	uint64_t InUse = 0;
	HWND hWnd = NULL;
	bool bParsing : 1 = false;
	bool bUserCancelled : 1 = false;
	bool bUsingConsole : 1 = false;
	bool bRunning : 1 = false;
#ifdef _DEBUG // Using DEBUG_ONLY macro doesn't work
	uint64_t TimeSpentSearching = 0;
	uint64_t TimeSpentFilling = 0;
	uint64_t TimeSpentInserting = 0;
	union {
		uint64_t TimeSpentDisassembling = 0;
		uint64_t TimeSpentAssembling;
	};
#endif
};

DWORD WINAPI Begin(void* args);
extern Data_t Data;
extern HANDLE hLogFile;
extern HANDLE hStdOut;

#ifndef UTIL_STRUCT_ONLY
struct Options_t {
	struct {
		bool bEnabled : 1 = false;
		bool bAntiDump : 1 = false;
		bool bEnableMasquerade : 1 = false;
		bool bNukeHeaders : 1 = false;
		bool bMitigateSideloading : 1 = false;
		bool bOnlyLoadMicrosoft : 1 = false;
		bool bMarkCritical : 1 = false;
		bool bAntiDebug : 1 = false;
		bool bAntiPatch : 1 = false;
		bool bAntiVM : 1 = false;
		bool bAllowHyperV : 1 = true;
		bool bAntiSandbox : 1 = false;
		bool bHideIAT : 1 = false;
		bool bAPIEmulation : 1 = false;
		bool bDelayedEntry : 1 = false;
		bool bDontCompressRsrc : 1 = true;
		bool bDirectSyscalls : 1 = false;
		bool bPartialUnpacking : 1 = false;
		uint64_t reserved : 14 = 0; // Reserved for future features
		int CompressionLevel = 5;
		PackerTypes_t Immitate = YAP;
		char Masquerade[MAX_PATH] = "C:\\Windows\\System32\\cmd.exe";
		char Message[64] = { 0 };
		int MutationLevel = 3;
		int EncodingCounts = 1;
	} Packing;

	struct {
		bool bEnabled : 1 = false;
		bool bRemoveData : 1 = false;
		bool bStrip : 1 = false;
		bool bStripDOSStub : 1 = false;
		bool bSubstitution : 1 = false;
		uint64_t reserved : 27 = 0;
		int MutationLevel = 0;
		uint64_t Rebase = 0;
	} Reassembly;

	struct {
		bool bTrueRandomSecNames : 1 = false;
		bool bSemiRandomSecNames : 1 = true;
		bool bFakeSymbols : 1 = true;
		bool bMutateAssembly : 1 = true;
		uint64_t reserved : 27 = 0;
		BYTE UPXVersionMajor = 5;
		BYTE UPXVersionMinor = 0;
		BYTE UPXVersionPatch = 1;
		char Sec1Name[9] = { 0 };
		char Sec2Name[9] = { 0 };
	} Advanced;

	struct {
		bool bDumpAsm : 1 = false;
		bool bDumpSections : 1 = false;
		bool bDumpFunctions : 1 = false;
		bool bGenerateBreakpoints : 1 = false;
		bool bGenerateMarks : 1 = false;
		bool bDisableRelocations : 1 = false;
		bool bStrictMutation : 1 = false;
		uint64_t reserved : 25 = 0;
	} Debug;
};

extern Options_t Options;
#endif // UTIL_STRUCT_ONLY

uint64_t rand64();

/*!
 * @brief Similar to MessageBox, opens a modal and waits for user input.
 * 
 * @param [in] pText Modal text.
 * @param [in] pTitle Modal title.
 * @param [in] uType Modal icon and buttons.
 * @return Which button was selected.
 */
int Modal(_In_ char* pText, _In_ char* pTitle = "Error", _In_ UINT uType = MB_OK);

bool LoadProject();
bool SaveProject();

template <typename T, typename __parent>
T child_cast(__parent p) {
	return *static_cast<T*>(&p);
}