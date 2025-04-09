/*!
 * @file util.hpp
 * @author undisassemble
 * @brief Utility definitions
 * @version 0.0.0
 * @date 2025-04-08
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
#include "version.hpp"
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

/*!
 * @brief Logging prefixes
 */
enum LoggingLevel_t : int {
	Nothing,      //!< No prefix
	Failed,       //!< [-] prefix
	Success,      //!< [+] prefix
	Warning,      //!< [*] prefix
	Info,         //!< [?] prefix
	Info_Extended //!< [>] prefix
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

/*!
 * @brief Buffer for raw data.
 */
struct Buffer {
	BYTE* pBytes;     //!< Pointer to raw data.
	uint64_t u64Size; //!< Size of `pBytes`.

	/*!
	 * @brief Merge with another buffer.
	 * 
	 * @param [in] Other Other buffer to merge with.
	 * @param [in] bFreeOther Release other buffers memory.
	 */
	void Merge(_In_ Buffer Other, _In_ bool bFreeOther = true);

	/*!
	 * @brief Allocate `Size` bytes.
	 * @remark This is not cumulative, if you have 5 bytes reserved and allocate 3 you get 3, not 8.
	 * 
	 * @param [in] Size Number of bytes to allocate.
	 */
	void Allocate(_In_ uint64_t Size);

	/*!
	 * @brief Release memory used by buffer.
	 */
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

/*!
 * @brief List it items.
 * 
 * @tparam T Type of data stored.
 */
template <typename T>
struct Vector {
	Buffer raw = { 0 };
	DWORD nItems = 0;
	bool bExponentialGrowth : 1 = false; //!< Whether extra memory should be reserved when limit reached, faster on larger vectors.
	bool bCannotBeReleased : 1 = false;  //!< When enabled `Release()` does nothing. Use if the buffer is within another memory block.

	/*!
	 * @brief Reserves additional memory.
	 * @remark Unlike `Buffer::Allocate(_In_ uint64_t Size)`, this is cumulative and adds additional memory.
	 * 
	 * @param [in] nItems Number of items to 
	 */
	void Reserve(_In_ int nItems) {
		raw.Allocate(raw.u64Size + nItems * sizeof(T));
	}

	/*!
	 * @brief Merge with another vector.
	 * 
	 * @param [in] Other Other vector to merge with.
	 * @param [in] bFreeOther Don't free the other vector.
	 */
	void Merge(_In_ Vector<T> Other, _In_ bool bFreeOther = false) {
		raw.u64Size = nItems * sizeof(T);
		raw.Merge(Other.raw, false);
		if (bFreeOther) Other.Release();
		nItems += Other.nItems;
		Data.InUse += Other.nItems * sizeof(T);
	}

	/*!
	 * @brief Number of items in the vector.
	 * 
	 * @return Number of items.
	 */
	size_t Size() {
		return nItems;
	}

	/*!
	 * @brief Total number of items that can fit before more memory will be reserved.
	 * 
	 * @return Number of items.
	 */
	size_t Capacity() {
		return raw.u64Size / sizeof(T);
	}

	/*!
	 * @brief Reserve memory based on number of items.
	 */
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

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& At(_In_ DWORD i) {
		if (!raw.pBytes || !raw.u64Size || Size() <= i) {
			T ret;
			ZeroMemory(&ret, sizeof(T));
			return ret;
		}
		return ((T*)raw.pBytes)[i];
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	T& operator[](_In_ int i) {
		return At(i);
	}

	/*!
	 * @brief Get item at index i.
	 * 
	 * @param [in] i Index.
	 * @return Item.
	 */
	const T& operator[](_In_ int i) const {
		return At(i);
	}

	/*!
	 * @brief Push item to end of vector.
	 * 
	 * @param [in] Item Item to push.
	 */
	void Push(_In_ T Item) {
		if (bCannotBeReleased) return;
		nItems++;
		Grow();
		memcpy(raw.pBytes + (nItems - 1) * sizeof(T), &Item, sizeof(T));
		Data.InUse += sizeof(T);
	}

	/*!
	 * @brief Push vector of items to end of vector.
	 * 
	 * @param [in] Items Items to push.
	 */
	void Push(_In_ Vector<T> Items) {
		for (int i = 0; i < Items.Size(); i++) {
			Push(Items[i]);
		}
	}

	/*!
	 * @brief Pop item from end vector.
	 * 
	 * @return Popped item.
	 */
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

	/*!
	 * @brief Replace item at index i.
	 * @deprecated Use `operator[]` instead.
	 * 
	 * @param [in] i Index of item to replace.
	 * @param [in] Item Item to replace it with.
	 */
	void Replace(_In_ DWORD i, _In_ T Item) {
		if (i < Size()) {
			((T*)raw.pBytes)[i] = Item;
		}
	}

	/*!
	 * @brief Replace single element with vector.
	 * 
	 * @param [in] i Index to replace.
	 * @param [in] Items Items to replace it with.
	 */
	void Replace(_In_ DWORD i, _In_ Vector<T> Items) {
		if (!Items.Size() || i >= Size()) return;
		Replace(i, Items[0]);
		Items.nItems--;
		Items.raw.pBytes += sizeof(T);
		Items.raw.u64Size -= sizeof(T);
		Insert(i + 1, Items);
		Items.raw.u64Size += sizeof(T);
		Items.raw.pBytes -= sizeof(T);
		Items.nItems++;
	}

	/*!
	 * @brief Replaces multiple elements with vector.
	 * 
	 * @param [in] i Index to begin replacement.
	 * @param [in] Items Items to replace with.
	 */
	void Overwrite(_In_ DWORD i, _In_ Vector<T> Items) {
		for (int j = 0; j < Items.Size() && i < Size(); j++ && i++) {
			((T*)raw.pBytes)[i] = Items[j];
		}
	}

	/*!
	 * @brief Release memory being used.
	 */
	void Release() {
		if (!bCannotBeReleased) {
			raw.Release();
			Data.InUse -= sizeof(T) * nItems;
			nItems = 0;
		}
	}

	/*!
	 * @brief Insert item at index.
	 * 
	 * @param [in] i Index to insert item.
	 * @param [in] Item Item to be inserted.
	 */
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

	/*!
	 * @brief Insert multiple items at index.
	 * 
	 * @param [in] i Index to insert items.
	 * @param [in] Items Items to be inserted.
	 */
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

	/*!
	 * @brief Remove item at idex.
	 * 
	 * @param [in] i Index to remove item from.
	 */
	void Remove(_In_ DWORD i) {
		if (!raw.u64Size || !raw.pBytes || i >= Size() || bCannotBeReleased) return;
		memcpy(raw.pBytes + sizeof(T) * i, raw.pBytes + sizeof(T) * (i + 1), (nItems * sizeof(T)) - sizeof(T) * (i + 1));
		nItems--;
		Data.InUse -= sizeof(T);
	}

	/*!
	 * @brief Finds an item.
	 * 
	 * @param [in] Item Item to search for.
	 * @return Index of item.
	 * @retval -1 Not found.
	 */
	int Find(_In_ T Item) {
		for (int i = 0, n = Size(); i < n; i++) {
			if (!memcmp(&Item, &((T*)raw.pBytes)[i], sizeof(T))) return i;
		}
		return -1;
	}

	/*!
	 * @brief Checks to see if a matching item exists.
	 * 
	 * @param [in] Item Item to search for.
	 * @retval true Present.
	 * @retval false Not present.
	 */
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
	int Theme = 0;
};

extern Settings_t Settings;
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
void SaveSettings();
void LoadSettings();