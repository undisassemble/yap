/*!
 * @file pe.hpp
 * @author undisassemble
 * @brief Portable executable parser definitions
 * @version 0.0.0
 * @date 2025-04-18
 * @copyright MIT License
 */

#pragma once

#include "util.hpp"

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
 * @brief Encodes an array of relocation RVAs into a valid relocation directory.
 * @note Relocations must be sorted from least to greatest.
 * 
 * @param [in] Relocations Relocation RVAs.
 * @return Raw relocation section.
 */
Buffer GenerateRelocSection(_In_ Vector<DWORD> Relocations);

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
	 * @param [in] sFileName File name.
	 */
	PE(_In_ char* sFileName);
	
	/*!
	 * @brief Parses PE from file.
	 * 
	 * @param [in] hFile File handle.
	 */
	PE(_In_ HANDLE hFile);
	
	/*!
	 * @brief Duplicates an existing PE.
	 * 
	 * @param [in] pOther PE to duplicate. 
	 */
	PE(_In_ PE* pOther);

	/*!
	 * @brief Retrieves the TLS callback array (can be written to/modified).
	 * 
	 * @return Pointer to TLS callback array.
	 * @retval NULL No TLS callbacks are present or unable to retrieve.
	 */
	uint64_t* GetTLSCallbacks();

	/*!
	 * @brief Parses a file.
	 * 
	 * @param [in] hFile File handle.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool ParseFile(_In_ HANDLE hFile);

	/*!
	 * @brief Changes a PEs base address and handles relocations.
	 * 
	 * @param [in] u64NewBase New base address.
	 */
	void RebaseImage(_In_ uint64_t u64NewBase);

	/*!
	 * @brief Writes data at the RVA.
	 * 
	 * @param [in] dwRVA RVA to write to.
	 * @param [in] pData Data to be written.
	 * @param [in] szData Size of data in `pData`.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData);

	/*!
	 * @brief Reads data at the RVA.
	 * 
	 * @param [in] dwRVA RVA to read from.
	 * @param [out] pData Buffer to contain data.
	 * @param [in] szData Size of `pData`.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData);

	/*!
	 * @brief Writes data at the RVA.
	 * 
	 * @tparam T Type to be written.
	 * @param [in] dwRVA RVA to write to.
	 * @param [in] Data Data to be written.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	template <typename T>
	bool WriteRVA(_In_ DWORD dwRVA, _In_ T Data) {
		return WriteRVA(dwRVA, &Data, sizeof(T));
	}

	/*!
	 * @brief Reads data at the RVA.
	 * 
	 * @tparam T Type to be read.
	 * @param [in] dwRVA RVA to read.
	 * @return Data read, zero-filled if RVA is invalid.
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
	 * @param [in] wIndex Index of section to delete.
	 */
	virtual void DeleteSection(_In_ WORD wIndex);

	/*!
	 * @brief Overwrite a section with new data.
	 * 
	 * @param [in] wIndex Index of section to overwrite.
	 * @param [in] pBytes Bytes to be replaced with (optional).
	 * @param [in] szBytes Size of `pBytes` (optional).
	 */
	void OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes);

	/*!
	 * @brief Inserts a new section.
	 * 
	 * @param [in] wIndex Index of section.
	 * @param [in] pBytes Bytes of section data (optional).
	 * @param [in] Header Section header.
	 */
	void InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header);

	/*!
	 * @brief Finds the section containing the raw address.
	 * 
	 * @param [in] dwRaw Raw address to search for.
	 * @return Index of section.
	 * @retval _UI16_MAX Not found.
	 */
	WORD FindSectionByRaw(_In_ DWORD dwRaw);

	/*!
	 * @brief Remove the DOS stub.
	 */
	void StripDosStub();

	/*!
	 * @brief Gets import tables.
	 * 
	 * @return Pointer to import table entries.
	 * @retval NULL No import table or unable to retrieve imports.
	 */
	IAT_ENTRY* GetIAT();

	/*!
	 * @brief Removes the PE overlay.
	 */
	void DiscardOverlay();

	/*!
	 * @brief Gets the file offset for the overlay.
	 * 
	 * @return Offset of the overlay.
	 * @retval NULL No overlay present.
	 */
	DWORD GetOverlayOffset();

	/*!
	 * @brief Finds the section containing the RVA.
	 * 
	 * @param [in] dwRVA RVA to search for.
	 * @return Section index.
	 * @retval _UI16_MAX Not found.
	 */
	WORD FindSectionByRVA(_In_ DWORD dwRVA);

	/*!
	 * @brief Translates a runtime offset to a file offset.
	 * 
	 * @param [in] dwRVA RVA to translate.
	 * @return File offset.
	 * @retval NULL Unable to translate.
	 */
	DWORD RVAToRaw(_In_ DWORD dwRVA);

	/*!
	 * @brief Translates a file offset to a runtime offset.
	 * 
	 * @param [in] dwRaw File offset.
	 * @return Virtual address.
	 * @retval NULL Unable to translate.
	 */
	DWORD RawToRVA(_In_ DWORD dwRaw);

	/*!
	 * @brief Formats and writes PE to disk.
	 * 
	 * @param [in] hFile Handle of file to write to.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool ProduceBinary(_In_ HANDLE hFile);

	/*!
	 * @brief Formats and writes PE to disk.
	 * 
	 * @param [in] sName Name of file to write to.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool ProduceBinary(_In_ char* sName);

	/*!
	 * @brief Gets RVAs of exported functions.
	 * 
	 * @return Exported RVAs.
	 */
	Vector<DWORD> GetExportedSymbolRVAs();

	/*!
	 * @brief Gets names of exported functions.
	 * 
	 * @return Exported names.
	 */
	Vector<char*> GetExportedSymbolNames();

	/*!
	 * @brief Gets list of imported DLLs.
	 * 
	 * @return Imported DLL descriptors.
	 */
	Vector<IMAGE_IMPORT_DESCRIPTOR> GetImportedDLLs();

	/*!
	 * @brief Reads string at RVA.
	 * 
	 * @param [in] dwRVA RVA to read.
	 * @return Pointer to string.
	 * @retval NULL Invalid/unable to read.
	 */
	char* ReadRVAString(_In_ DWORD dwRVA);

	/*!
	 * @brief Gets list of addresses that get relocated.
	 * 
	 * @return Relocation RVAs.
	 */
	Vector<DWORD> GetRelocations();

	/*!
	 * @brief Find symbol from the symbol table by name.
	 * 
	 * @param [in] sName Name of symbol to find.
	 * @return Symbol info, zero-filled if not found.
	 */
	IMAGE_SYMBOL FindSymbol(_In_ char* sName);

	/*!
	 * @brief Get all symbol names.
	 * 
	 * @return Symbol names.
	 */
	Vector<char*> GetSymbolNames();

	/*!
	 * @brief Get symbol by index in table.
	 * 
	 * @param [in] i Index of symbol.
	 * @return Symbol info, zero-filled if invalid.
	 */
	IMAGE_SYMBOL GetSymbol(_In_ int i);
};