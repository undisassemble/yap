#pragma once

// Headers
#include "platform.hpp"
#include "version.hpp"
#include <limits.h>
typedef uint64_t QWORD;
#ifndef UTIL_STRUCT_ONLY
#include <asmjit/asmjit.h>
#include <Zydis/Zydis.h>
using namespace asmjit;
using namespace x86;

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_INFO_EXTRA  "\x1B[36m[>]\x1B[39m "
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "
#define MODULE_YAP "YAP"
#define MODULE_VM "VM"
#define MODULE_PACKER "Packer"
#define MODULE_REASSEMBLER "ReAsm"
enum LoggingLevel_t : int {
	Nothing,
	Failed,
	Success,
	Warning,
	Info,
	Info_Extended
};
void LOG(LoggingLevel_t level, char* mod, char* str, ...);

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

struct Buffer {
	BYTE* pBytes;
	uint64_t u64Size;

	void Merge(_In_ Buffer Other, _In_ bool bDontFree = false);
	void Allocate(_In_ uint64_t Size);
	void Release();
};

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

template <typename T>
struct Vector {
	Buffer raw = { 0 };
	DWORD nItems = 0;
	bool bExponentialGrowth : 1 = false; // Faster on larger vectors
	bool bCannotBeReleased : 1 = false; // If the buffer is within another memory block

	void Merge(_In_ Vector<T> Other, _In_ bool bDontFree = false) {
		raw.u64Size = nItems * sizeof(T);
		raw.Merge(Other.raw, true);
		if (!bDontFree) Other.Release();
		nItems += Other.nItems;
		Data.InUse += Other.nItems * sizeof(T);
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
			raw.Allocate(sizeof(T) * (bExponentialGrowth ? 10 : 1));
			if (!raw.pBytes) {
				DebugBreak();
				exit(1);
			}
			ZeroMemory(raw.pBytes, raw.u64Size);
		}
		
		// Expand buffer
		else if (raw.u64Size < nItems * sizeof(T)) {
			uint64_t OldSize = raw.u64Size;
			uint64_t NewSize = OldSize;
			if (bExponentialGrowth) {
				while (NewSize < nItems * sizeof(T)) {
					NewSize = sizeof(T) * (NewSize / sizeof(T)) * 1.1;
				}
			} else {
				NewSize = nItems * sizeof(T);
			}
			raw.Allocate(NewSize);
			if (!raw.pBytes) {
				DebugBreak();
				exit(1);
			}
			ZeroMemory(raw.pBytes + OldSize, NewSize - OldSize);
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

	T operator[](_In_ int i) {
		return At(i);
	}

	void Push(_In_ T Item) {
		if (bCannotBeReleased) return;
		nItems++;
		Grow();
		memcpy(raw.pBytes + (nItems - 1) * sizeof(T), &Item, sizeof(T));
		Data.InUse += sizeof(T);
	}

	void Push(Vector<T> Items) {
		for (int i = 0; i < Items.Size(); i++) {
			Push(Items[i]);
		}
	}

	T Pop() {
		if (!raw.u64Size || !raw.pBytes || bCannotBeReleased) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		T ret = At(Size() - 1);
		Data.InUse -= sizeof(T);
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
		Replace(i, Item[0]);
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
			((T*)raw.pBytes)[i] = Item[j];
		}
	}

	void Release() {
		if (!bCannotBeReleased) {
			raw.Release();
			Data.InUse -= sizeof(T) * nItems;
			nItems = 0;
		}
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
		Data.InUse -= sizeof(T);
	}

	/// <summary>
	/// Finds item in array
	/// </summary>
	/// <param name="Item">Item to find</param>
	/// <returns>Index of item, or -1 if not found</returns>
	int Find(_In_ T Item) {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &((T*)raw.pBytes)[i], sizeof(T))) return i;
		}
		return -1;
	}

	bool Includes(_In_ T Item) {
		return Find(Item) >= 0;
	}

	//~Vector() {
		//Release();
	//}
};

struct ToVirt_t {
	bool bRemoveExport : 1 = true;
	char Name[25] = { 0 };
};

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

	// Requires packing
	struct {
		bool bEnabled : 1 = false;
		bool bVirtEntry : 1 = false;
		Vector<ToVirt_t> VMFuncs;
	} VM;

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
		bool bDeleteVirtualizedFunctions : 1 = false;
		bool bTrueRandomSecNames : 1 = false;
		bool bSemiRandomSecNames : 1 = true;
		bool bFakeSymbols : 1 = true;
		bool bMutateAssembly : 1 = true;
		uint64_t reserved : 27 = 0;
		BYTE UPXVersionMajor = 5;
		BYTE UPXVersionMinor = 0;
		BYTE UPXVersionPatch = 0;
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

struct Settings_t {
	bool bCheckForUpdates = true;
	int Theme = 0;
};

extern Settings_t Settings;
extern Options_t Options;
#endif // UTIL_STRUCT_ONLY

uint64_t rand64();

/// 
/// Similar to MessageBox, opens a modal and waits for user input.
/// 
int Modal(_In_ char* pText, _In_ char* pTitle = "Error", _In_ UINT uType = MB_OK);

bool LoadProject();
bool SaveProject();
void SaveSettings();
void LoadSettings();