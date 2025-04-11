/*!
 * @file packer.hpp
 * @author undisassemble
 * @brief Packer definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#pragma once

#include "asm.hpp"
#include "LzmaEnc.h"

/*!
 * @brief Result of a SHA256 operation.
 * @bug This is wrong because of endianness.
 */
struct Sha256Digest {
	struct {
		uint64_t high = 0; //!< Bytes 0-7
		uint64_t low = 0;  //!< Bytes 8-15
	} high;
	struct {
		uint64_t high = 0; //!< Bytes 16-23
		uint64_t low = 0;  //!< Bytes 24-31
	} low;
};

/*!
 * @brief SDK function request.
 */
struct RequestedFunction {
	bool bRequested = false; //!< If the function is required.
	DWORD dwRVA = 0;         //!< RVA where the function address needs to be written.
	Label Func;              //!< Function entry label.
};

/*!
 * @brief Various data needed by the packer.
 * @todo Clean this up.
 */
struct _ShellcodeData {
	uint64_t BaseAddress = 0;
	int64_t BaseOffset = 0;
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

/*!
 * @brief Pack the PE.
 * 
 * @param [in] pOriginal PE to be packed.
 * @param [out] pPackedBinary Where to store the packed PE.
 * @retval true Success.
 * @retval false Failure.
 */
bool Pack(_In_ Asm* pOriginal, _Out_ Asm* pPackedBinary);