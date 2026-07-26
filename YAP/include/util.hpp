/*!
 * @file util.hpp
 * @author undisassemble
 * @brief Utility definitions
 * @version 0.0.0
 * @date 2026-07-25
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
#include <unordered_map>
#include <variant>
#include <string>
#include "version.hpp"
#include "relib/relib.hpp"

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "
#define MODULE_YAP "YAP"
#define MODULE_VM "VM"
#define MODULE_PACKER "Pack"
#define MODULE_REASSEMBLER "Asm"
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

struct Data_t {
	char ConfigPath[MAX_PATH] = { 0 };
	Buffer Target = Buffer(MAX_PATH), Output = Buffer(MAX_PATH);
	float fTotalProgress = 0.f;
	float fTaskProgress = 0.f;
	char* sTask = NULL;
	State_t State = Idle;
	HWND hWnd = NULL;
	bool bParsing : 1 = false;
	bool bUserCancelled : 1 = false;
	bool bUsingConsole : 1 = false;
	bool bRunning : 1 = false;
};

DWORD WINAPI Begin(void* args);
extern Data_t Data;
extern HANDLE hLogFile;
extern HANDLE hStdOut;
extern std::unordered_map<std::string_view, std::variant<bool, int, Buffer, uint64_t>> config;
extern std::unordered_map<std::string_view, std::variant<bool, int>> settings;
extern Vector<std::pair<LoggingLevel_t, char*>> logs;

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

void LoadDefaultConfig();
bool LoadConfig();
bool SaveConfig();
bool LoadSettings();
void ClearLogs();

template <typename T, typename __parent>
T child_cast(__parent p) {
	return *static_cast<T*>(&p);
}