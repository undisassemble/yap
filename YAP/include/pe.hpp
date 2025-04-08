/*!
 * @file pe.hpp
 * @author undisassemble
 * @brief Portable executable parser definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#pragma once

#include "util.hpp"
#include <winnt.h>

/*!
 * @brief Status of PE class.
 */
enum PEStatus_t : BYTE {
	Normal = 0,     //!< No noticed errors
	NotSet = 1,     //!< Parser has not been given a file
	NoFile = 2,     //!< File provided does not exist
	NotPE = 3,      //!< File provided is not a PE or is corrupt
	Unsupported = 4 //!< PE is an unsupported architecture or format
};

typedef struct {
	DWORD LookupRVA;
	DWORD TimeStamp;
	DWORD Forward;
	DWORD NameRVA;
	DWORD ThunkRVA;
} IAT_ENTRY;

/*!
 * @brief Parses portable executable formats.
 */
class PE {
protected:
	DWORD OverlayOffset = 0;    //!< Raw offset of the overlay.
	IMAGE_SYMBOL* pSyms = NULL; //!< Image symbol table.

public:
	PE();
	virtual ~PE();

	PEStatus_t Status = NotSet; //!< Status of PE.
	Buffer DosStub = { 0 }; //!< Image DOS stub.
	Buffer Overlay = { 0 }; //!< Image overlay.
	Vector<Buffer> SectionData; //!< Raw data of image sections.
	Vector<IMAGE_SECTION_HEADER> SectionHeaders; //!< Image section headers.
	IMAGE_DOS_HEADER DosHeader = { 0 }; //!< Image DOS header.
	IMAGE_NT_HEADERS64 NTHeaders = { 0 }; //!< Image NT headers.

	/*!
	 * @brief Parses PE from file.
	 * 
	 * @param sFileName File name.
	 */
	PE(_In_ char* sFileName);
	
	/*!
	 * @brief Parses PE from file.
	 * 
	 * @param hFile File handle.
	 */
	PE(_In_ HANDLE hFile);
	
	/*!
	 * @brief Duplicates an existing PE.
	 * 
	 * @param pOther PE to duplicate. 
	 */
	PE(_In_ PE* pOther);

	/*!
	 * @brief Retrieves the TLS callback array (can be written to/modified).
	 * 
	 * @return uint64_t* Pointer to TLS callback array, `NULL` if no TLS callbacks are present.
	 */
	uint64_t* GetTLSCallbacks();

	/*!
	 * @brief Parses a file.
	 * 
	 * @param hFile File handle.
	 * @return true Success.
	 * @return false Failure.
	 */
	bool ParseFile(_In_ HANDLE hFile);

	/*!
	 * @brief Changes a PEs base address and handles relocations.
	 * 
	 * @param u64NewBase New base address.
	 */
	void RebaseImage(_In_ uint64_t u64NewBase);

	/*!
	 * @brief Writes data at the RVA.
	 * @todo Change `pData` and `szData` to `Buffer`.
	 * @todo Return status.
	 * 
	 * @param dwRVA RVA to write to.
	 * @param pData Data to be written.
	 * @param szData Size of data in `pData`.
	 */
	void WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData);

	/*!
	 * @brief Reads data at the RVA.
	 * @todo Change `pData` and `szData` to `Buffer` or have it return a `Buffer`.
	 * 
	 * @param dwRVA RVA to read from.
	 * @param pData Buffer to contain data.
	 * @param szData Size of `pData`.
	 */
	void ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData);

	/*!
	 * @brief Writes data at the RVA.
	 * @todo Return status.
	 * 
	 * @tparam T Type to be written.
	 * @param dwRVA RVA to write to.
	 * @param Data Data to be written.
	 */
	template <typename T>
	void WriteRVA(_In_ DWORD dwRVA, _In_ T Data) {
		WriteRVA(dwRVA, &Data, sizeof(T));
	}

	/*!
	 * @brief Reads data at the RVA.
	 * 
	 * @tparam T Type to be read.
	 * @param dwRVA RVA to read.
	 * @return T Data read, zero-filled if RVA is invalid.
	 */
	template <typename T>
	T ReadRVA(_In_ DWORD dwRVA) {
		T ret;
		ReadRVA(dwRVA, &ret, sizeof(T));
		return ret;
	}

	/*!
	 * @brief Fixes headers and moves sections.
	 */
	void FixHeaders();

	/*!
	 * @brief Deletes a section.
	 * 
	 * @param wIndex Index of section to delete.
	 */
	virtual void DeleteSection(_In_ WORD wIndex);

	/*!
	 * @brief Overwrite a section with new data.
	 * @todo Replace `pBytes` and `szBytes` with `Buffer`.
	 * 
	 * @param wIndex Index of section to overwrite.
	 * @param pBytes Bytes to be replaced with.
	 * @param szBytes Size of `pBytes`.
	 */
	void OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes);

	/*!
	 * @brief Inserts a new section.
	 * 
	 * @param wIndex Index of section.
	 * @param pBytes Bytes of section data.
	 * @param Header Section header.
	 */
	void InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header);

	/*!
	 * @brief Finds the section containing the raw address.
	 * 
	 * @param dwRaw Raw address to search for.
	 * @return WORD Index of section or `_UI16_MAX` if not found.
	 */
	WORD FindSectionByRaw(_In_ DWORD dwRaw);

	/*!
	 * @brief Remove the DOS stub.
	 */
	void StripDosStub();

	/*!
	 * @brief Gets import tables.
	 * 
	 * @return IAT_ENTRY* Import table entries.
	 */
	IAT_ENTRY* GetIAT();

	/*!
	 * @brief Removes the PE overlay.
	 */
	void DiscardOverlay();

	/*!
	 * @brief Gets the file offset for the overlay.
	 * 
	 * @return DWORD Offset of the overlay or `NULL` if there is no overlay.
	 */
	DWORD GetOverlayOffset();

	/*!
	 * @brief Finds the section containing the RVA.
	 * 
	 * @param dwRVA RVA to search for.
	 * @return WORD Section index or `_UI16_MAX` if not found.
	 */
	WORD FindSectionByRVA(_In_ DWORD dwRVA);

	/*!
	 * @brief Translates a runtime offset to a file offset.
	 * @todo Ensure this works when getting virtual address that doesn't exist raw.
	 * 
	 * @param dwRVA RVA to translate.
	 * @return DWORD File offset.
	 */
	DWORD RVAToRaw(_In_ DWORD dwRVA);

	/*!
	 * @brief Translates a file offset to a runtime offset.
	 * @todo Ensure this works when getting raw address that never gets loaded.
	 * 
	 * @param dwRaw File offset.
	 * @return DWORD RVA.
	 */
	DWORD RawToRVA(_In_ DWORD dwRaw);

	/*!
	 * @brief Formats and writes PE to disk.
	 * 
	 * @param hFile Handle of file to write to.
	 * @return true Success.
	 * @return false Failure.
	 */
	bool ProduceBinary(_In_ HANDLE hFile);

	/*!
	 * @brief Formats and writes PE to disk.
	 * 
	 * @param sName Name of file to write to.
	 * @return true Success.
	 * @return false Failure.
	 */
	bool ProduceBinary(_In_ char* sName);

	/*!
	 * @brief Gets RVAs of exported functions.
	 * @todo Rename to GetExportedSymbolRVAs
	 * 
	 * @return Vector<DWORD> Exported RVAs.
	 */
	Vector<DWORD> GetExportedFunctionRVAs();

	/*!
	 * @brief Gets names of exported functions.
	 * @todo Rename to GetExportedSymbolNames
	 * 
	 * @return Vector<char*> Exported names.
	 */
	Vector<char*> GetExportedFunctionNames();

	/*!
	 * @brief Gets list of imported DLLs.
	 * 
	 * @return Vector<IMAGE_IMPORT_DESCRIPTOR> Imported DLL descriptors.
	 */
	Vector<IMAGE_IMPORT_DESCRIPTOR> GetImportedDLLs();

	/*!
	 * @brief Reads string at RVA.
	 * 
	 * @param dwRVA RVA to read.
	 * @return char* String read or `NULL` if invalid.
	 */
	char* ReadRVAString(_In_ DWORD dwRVA);

	/*!
	 * @brief Gets list of addresses that get relocated.
	 * 
	 * @return Vector<DWORD> Relocation RVAs.
	 */
	Vector<DWORD> GetRelocations();

	/*!
	 * @brief Find symbol from the symbol table by name.
	 * 
	 * @param sName Name of symbol to find.
	 * @return IMAGE_SYMBOL Symbol info, zero-filled if not found.
	 */
	IMAGE_SYMBOL FindSymbol(_In_ char* sName);

	/*!
	 * @brief Get all symbol names.
	 * 
	 * @return Vector<char*> Symbol names.
	 */
	Vector<char*> GetSymbolNames();

	/*!
	 * @brief Get symbol by index in table.
	 * 
	 * @param i Index of symbol.
	 * @return IMAGE_SYMBOL Symbol info, zero-filled if invalid.
	 */
	IMAGE_SYMBOL GetSymbol(_In_ int i);
};