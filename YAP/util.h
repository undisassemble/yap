#pragma once

// Headers
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <winternl.h>
typedef uint64_t QWORD;
#ifndef UTIL_STRUCT_ONLY
#include <asmjit.h>
#include "Zydis/Zydis.h"
using namespace asmjit;
using namespace x86;

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_INFO_EXTRA LOG_INFO
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "
#define MODULE_YAP "Yap"
#define MODULE_VM "VM"
#define MODULE_PACKER "Packer"
#define MODULE_REASSEMBLER "ReAsm"
#define LOG(level, mod, str, ...) if (level <= ::Settings.Logging) { char _log_buf[128]; if (!level && ::Data.bUsingConsole) { snprintf(_log_buf, 128, "[" mod "]: \t" str, ##__VA_ARGS__); WriteConsoleA(hStdOut, _log_buf, strlen(_log_buf), NULL, NULL); } else if (level && ::Data.bUsingConsole) { snprintf(_log_buf, 128, "%s[" mod "]: \t" str, level == LoggingLevel_t::Failed ? LOG_ERROR : (level == LoggingLevel_t::Success ? LOG_SUCCESS : (level == LoggingLevel_t::Warning ? LOG_WARNING : (level == LoggingLevel_t::Info ? LOG_INFO : LOG_INFO_EXTRA))), ##__VA_ARGS__); WriteConsoleA(hStdOut, _log_buf, strlen(_log_buf), NULL, NULL); } if (level && ::hLogFile) { snprintf(_log_buf, 128, "%s[" mod "]: \t" str, level == LoggingLevel_t::Failed ? "[-] " : (level == LoggingLevel_t::Success ? "[+] " : (level == LoggingLevel_t::Warning ? "[*] " : (level == LoggingLevel_t::Info ? "[?] " : "[?] "))), ##__VA_ARGS__); WriteFile(hLogFile, _log_buf, strlen(_log_buf), NULL, NULL); } }

// Macros
#define IMGUI_TOGGLE(str, var) { bool _TEMP_BOOL = var; if(ImGui::Checkbox(str, &_TEMP_BOOL)) { var = _TEMP_BOOL; } } // Allows ImGui::Checkbox to be used with bitfields
#define ASMJIT_LIBRARY_VERSION_MAJOR(version) ((version & 0xFF0000) >> 16)
#define ASMJIT_LIBRARY_VERSION_MINOR(version) ((version & 0xFF00) >> 8)
#define ASMJIT_LIBRARY_VERSION_PATCH(version) (version & 0xFF)
#define countof(x) (sizeof(x) / sizeof(*x))

// Version
#define __YAP_VERSION__ "0.0.0"
#ifdef _DEBUG
#define __YAP_BUILD__ "DEBUG"
#define DEBUG_ONLY(x) x
#define RELEASE_ONLY(x)
#define __YAP_VERSION_NUM__ 0xFF000000
#else
#define __YAP_BUILD__ "RELEASE"
#define DEBUG_ONLY(x)
#define RELEASE_ONLY(x) x
#define __YAP_VERSION_NUM__ 0x00000000
#endif

const int VMMinimumSize = 21;

enum SpeedSettings_t : int {
	PrioAuto,
	PrioSpeed,
	PrioMem
};

enum LoggingLevel_t : int {
	Nothing,
	Failed,
	Success,
	Warning,
	Info,
	Info_Extended
};

enum PackerTypes_t : int {
	YAP,
	Themida,
	WinLicense,
	UPX,
	MPRESS,
	Enigma,
	ExeStealth
};
#endif // UTIL_STRUCT_ONLY

struct Buffer {
	BYTE* pBytes;
	uint64_t u64Size;

	void Merge(_In_ Buffer Other, _In_ bool bDontFree = false) {
		if (!Other.pBytes || !Other.u64Size) {
			return;
		} else if (!pBytes || !u64Size) {
			pBytes = Other.pBytes;
			u64Size = Other.u64Size;
		} else {
			u64Size += Other.u64Size;
			pBytes = reinterpret_cast<BYTE*>(realloc(pBytes, u64Size));
			if (!pBytes) {
				DebugBreak();
				exit(1);
			}
			memcpy(pBytes + u64Size - Other.u64Size, Other.pBytes, Other.u64Size);
			if (!bDontFree) {
				free(Other.pBytes);
				Other.pBytes = NULL;
				Other.u64Size = 0;
			}
		}
	}
};

template <typename T>
struct Vector {
	Buffer raw = { 0 };
	DWORD nItems = 0;
	bool bExponentialGrowth : 1 = false; // Faster on larger vectors
	bool bCannotBeReleased : 1 = false; // If the buffer is within another memory block

	void Merge(_In_ Vector<T> Other, _In_ bool bDontFree = false) {
		raw.u64Size = nItems * sizeof(T);
		raw.Merge(Other.raw, bDontFree);
		nItems += Other.nItems;
	}

	size_t Size() {
		return nItems;
	}

	size_t Capacity() {
		return raw.u64Size / sizeof(T);
	}

	void Grow() {
		if (bCannotBeReleased) return;

		// Create buffer
		if (raw.u64Size < sizeof(T) || !raw.pBytes || !raw.u64Size) {
			raw.u64Size = sizeof(T) * (bExponentialGrowth ? 10 : 1);
			raw.pBytes = reinterpret_cast<BYTE*>(realloc(raw.pBytes, raw.u64Size));
			if (!raw.pBytes) {
				DebugBreak();
				exit(1);
			}
			ZeroMemory(raw.pBytes, raw.u64Size);
		}
		
		// Expand buffer
		else if (raw.u64Size < nItems * sizeof(T)) {
			uint64_t OldSize = raw.u64Size;
			if (bExponentialGrowth) {
				while (raw.u64Size < nItems * sizeof(T)) {
					raw.u64Size = sizeof(T) * (raw.u64Size / sizeof(T)) * 1.1;
				}
			} else {
				raw.u64Size = nItems * sizeof(T);
			}
			raw.pBytes = reinterpret_cast<BYTE*>(realloc(raw.pBytes, raw.u64Size));
			if (!raw.pBytes) {
				DebugBreak();
				exit(1);
			}
			ZeroMemory(raw.pBytes + OldSize, raw.u64Size - OldSize);
		}
	}

	T At(_In_ DWORD i) {
		if (!raw.pBytes || !raw.u64Size || Size() <= i) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		return ((T*)raw.pBytes)[i];
	}

	void Push(_In_ T Item) {
		if (bCannotBeReleased) return;
		nItems++;
		Grow();
		memcpy(raw.pBytes + (nItems - 1) * sizeof(T), &Item, sizeof(T));
	}

	void Push(Vector<T> Items) {
		for (int i = 0; i < Items.Size(); i++) {
			Push(Items.At(i));
		}
	}

	T Pop() {
		if (!raw.u64Size || !raw.pBytes || bCannotBeReleased) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		T ret = At(Size() - 1);
		if (Size() == 1) {
			Release();
		} else {
			nItems--;
		}
		return ret;
	}

	void Replace(_In_ DWORD i, _In_ T Item) {
		if (i < Size()) {
			((T*)raw.pBytes)[i] = Item;
		}
	}

	// Replaces first instruction, inserts the remainder
	void Replace(_In_ DWORD i, _In_ Vector<T> Item) {
		if (!Item.Size() || i >= Size()) return;
		Replace(i, Item.At(0));
		Item.nItems--;
		Item.raw.pBytes += sizeof(T);
		Item.raw.u64Size -= sizeof(T);
		Insert(i + 1, Item);
		Item.raw.u64Size += sizeof(T);
		Item.raw.pBytes -= sizeof(T);
		Item.nItems++;
	}

	// Replaces instructions in order, size does not change
	void Overwrite(_In_ DWORD i, _In_ Vector<T> Item) {
		for (int j = 0; j < Item.Size() && i < Size(); j++ && i++) {
			((T*)raw.pBytes)[i] = Item.At(j);
		}
	}

	void Release() {
		if (raw.pBytes && !bCannotBeReleased) free(raw.pBytes);
		raw.pBytes = NULL;
		raw.u64Size = 0;
		nItems = 0;
	}

	void Insert(_In_ DWORD i, _In_ T Item) {
		if (i > Size() || bCannotBeReleased) return;
		if (i == Size()) {
			Push(Item);
			return;
		}
		DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
		nItems++;
		Grow();

		// Shift memory
		memmove(raw.pBytes + (i + 1) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - 1) * sizeof(T));
		
		// Insert item
		Replace(i, Item);
		DEBUG_ONLY(Data.TimeSpentInserting += GetTickCount64() - TickCount);
	}

	void Insert(_In_ DWORD i, _In_ Vector<T> Items) {
		if (i > Size() || bCannotBeReleased) return;
		DEBUG_ONLY(uint64_t TickCount = GetTickCount64());

		// Size stuff
		nItems += Items.nItems;
		Grow();

		// Add to end
		if (i == Size()) {
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}

		// Shift and insert
		else {
			memmove(raw.pBytes + (i + Items.nItems) * sizeof(T), raw.pBytes + i * sizeof(T), (nItems - i - Items.nItems) * sizeof(T));
			memcpy(raw.pBytes + i * sizeof(T), Items.raw.pBytes, Items.nItems * sizeof(T));
		}

		DEBUG_ONLY(Data.TimeSpentInserting += GetTickCount64() - TickCount);
	}

	void Remove(_In_ DWORD i) {
		if (!raw.u64Size || !raw.pBytes || i >= Size() || bCannotBeReleased) return;
		memcpy(raw.pBytes + sizeof(T) * i, raw.pBytes + sizeof(T) * (i + 1), (nItems * sizeof(T)) - sizeof(T) * (i + 1));
		nItems--;
	}

	bool Includes(_In_ T Item) {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &((T*)raw.pBytes)[i], sizeof(T))) return true;
		}
		return false;
	}

	//~Vector() {
		//Release();
	//}
};

struct Data_t {
	char Project[MAX_PATH] = { 0 };
	char SaveFileName[MAX_PATH] = { 0 };
	HWND hWnd = NULL;
	bool bParsing : 1 = false;
	bool bWaitingOnFile : 1 = false;
	bool bUserCancelled : 1 = false;
	bool bUsingConsole : 1 = false;
	bool bRunning : 1 = false;
#ifdef _DEBUG // Using DEBUG_ONLY macro doesnt work
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

struct ToVirt_t {
	bool bRemoveExport : 1 = true;
	char Name[25] = { 0 };
};

#ifndef UTIL_STRUCT_ONLY
struct Options_t {
	struct {
		bool bEnabled : 1 = true;
		bool bAntiDump : 1 = false;
		bool bEnableMasquerade : 1 = false;
		bool bNukeHeaders : 1 = false;
		bool bMitigateSideloading : 1 = false;
		bool bOnlyLoadMicrosoft : 1 = false;
		bool bMarkCritical : 1 = false;
		bool bAntiDebug : 1 = false;
		bool bAntiVM : 1 = false;
		bool bAllowHyperV : 1 = true;
		bool bAntiSandbox : 1 = false;
		bool bHideIAT : 1 = false;
		bool bDelayedEntry : 1 = false;
		bool bDontCompressRsrc : 1 = true;
		bool bDirectSyscalls : 1 = false;
		bool bPartialUnpacking : 1 = false;
		int CompressionLevel = 5;
		PackerTypes_t Immitate = YAP;
		char Masquerade[MAX_PATH] = "C:\\Windows\\System32\\cmd.exe";
		char Message[64] = { 0 };
		int MutationLevel = 3;
		int EncodingCounts = 1;
	} Packing;

	// Requires packing
	struct {
		bool bEnabled : 1 = false;
		bool bVirtEntry : 1 = false;
		Vector<ToVirt_t> VMFuncs;
	} VM;

	struct {
		bool bEnabled : 1 = false;
		bool bTest : 1 = false;
		bool bStrip : 1 = false;
		bool bSubstitution : 1 = false;
	} Reassembly;

#ifdef _DEBUG
	struct {
		bool bDumpAsm : 1 = false;
		bool bDumpSections : 1 = false;
		bool bDumpFunctions : 1 = false;
		bool bGenerateBreakpoints : 1 = false;
		bool bGenerateMarks : 1 = false;
		bool bDisableMutations : 1 = false;
		bool bDisableRelocations : 1 = false;

	} Debug;
#endif
};

struct Settings_t {
	bool bCheckForUpdates = true;
	SpeedSettings_t Opt = PrioAuto;
	LoggingLevel_t Logging = DEBUG_ONLY(Info_Extended) RELEASE_ONLY(Warning);
};

extern Settings_t Settings;
extern Options_t Options;
#endif // UTIL_STRUCT_ONLY