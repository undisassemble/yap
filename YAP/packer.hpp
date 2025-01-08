#pragma once

#include "asm.hpp"
#include "LzmaEnc.h"

struct Sha256Digest {
	struct {
		uint64_t high = 0;
		uint64_t low = 0;
	} high;
	struct {
		uint64_t high = 0;
		uint64_t low = 0;
	} low;
};

struct RequestedFunction {
	bool bRequested = false;
	DWORD dwRVA = 0;
	Label Func;
};

struct _ShellcodeData {
	uint64_t BaseAddress = 0;
	uint64_t OldPENewBaseRVA = 0;
	uint64_t PaddingNeeded = 0;
	uint64_t LoadedOffset = 0;
	uint64_t VMAbs = 0;
	uint64_t ImageBase = 0;
	uint64_t MessageBoxAddr = 0;
	BYTE EntryOff = 0;
	DWORD GetProcAddressOff = 0;
	DWORD GetModuleHandleWOff = 0;
	DWORD Sha256_InitOff = 0;
	DWORD Sha256_UpdateOff = 0;
	DWORD Sha256_FinalOff = 0;
	bool bUsingTLSCallbacks = false;

	struct {
		Vector<uint64_t> Relocations;
	} Relocations;

	struct {
		Label GetModuleHandleW;
		Label GetProcAddressByOrdinal;
		Label GetProcAddress;
		Label RtlZeroMemory;
		Label RelocDiff;
	} Labels;

	struct {
		BYTE EncodedProp[LZMA_PROPS_SIZE];
	} UnpackData;

	struct {
		// SDK
		int iIndex = -1;
		RequestedFunction CheckForDebuggers;
		RequestedFunction GetSelf;

		// Emulated
		int iKernel32 = -1;
		int iNtDLL = -1;
		RequestedFunction GetCurrentThread;
		RequestedFunction GetCurrentThreadId;
		RequestedFunction GetCurrentProcessId;
		RequestedFunction GetCurrentProcess;
		RequestedFunction GetTickCount64;
		RequestedFunction GetStdHandle;
		RequestedFunction GetLastError;
		RequestedFunction SetLastError;
		RequestedFunction GetProcAddress;
	} RequestedFunctions;

	struct {
		bool bWasAntiDump : 1 = false;
	} CarryData;

	struct {
		Sha256Digest LoaderHash;
		DWORD dwOffHeaderSum = 0;
	} AntiPatchData;
};

struct PackerOptions {
	bool bVM : 1;
	char* Message = NULL;
	char* sMasqueradeAs = NULL;
	Vector<DWORD> VMFuncs;
};

bool Pack(_In_ Asm* pOriginal, _In_ PackerOptions Options, _Out_ Asm* pPackedBinary);

#include "vm.hpp"