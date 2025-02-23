#pragma once

#include "util.hpp"

enum PEStatus_t : BYTE {
	Normal = 0,								// No noticed errors
	NotSet = 1,								// Parser has not been given a file
	NoFile = 2,								// File provided does not exist
	NotPE = 3,								// File provided is not a PE or is corrupt
	Unsupported = 4							// PE is an unsupported architecture or format
};

typedef struct {
	DWORD LookupRVA;
	DWORD TimeStamp;
	DWORD Forward;
	DWORD NameRVA;
	DWORD ThunkRVA;
} IAT_ENTRY;

/// 
/// Parses portable executable formats
/// 
class PE {
protected:
	DWORD OverlayOffset = 0;
public:
	PEStatus_t Status = NotSet;
	Buffer DosStub = { 0 };
	Buffer Overlay = { 0 };
	Vector<Buffer> SectionData;
	Vector<IMAGE_SECTION_HEADER> SectionHeaders;
	IMAGE_DOS_HEADER DosHeader = { 0 };
	IMAGE_NT_HEADERS64 NTHeaders = { 0 };

	/// 
	/// Parses PE from file.
	/// 
	PE(_In_ char* sFileName);
	
	/// 
	/// Parses PE from file.
	/// 
	PE(_In_ HANDLE hFile);

	/// 
	/// Creates empty PE object.
	/// 
	PE();

	/// 
	/// Duplicates an existing PE object.
	/// 
	PE(_In_ PE* pOther);

	virtual ~PE();

	/// 
	/// Retrieves the TLS callback array (can be written to/modified).
	/// `NULL` or points to `NULL` if no TLS callbacks are present.
	/// 
	uint64_t* GetTLSCallbacks();

	/// 
	/// Parses a file.
	/// 
	bool ParseFile(_In_ HANDLE hFile);

	/// 
	/// Changes a PEs base address (and handles relocations).
	/// 
	void RebaseImage(_In_ uint64_t u64NewBase);

	/// 
	/// Writes data at the RVA.
	/// 
	void WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData);
	
	/// 
	/// Reads data at the RVA.
	/// 
	void ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData);

	/// 
	/// Writes data at the RVA.
	/// 
	template <typename T>
	void WriteRVA(_In_ DWORD dwRVA, _In_ T Data) {
		WriteRVA(dwRVA, &Data, sizeof(T));
	}

	/// 
	/// Reads data at the RVA.
	/// 
	template <typename T>
	T ReadRVA(_In_ DWORD dwRVA) {
		T ret;
		ReadRVA(dwRVA, &ret, sizeof(T));
		return ret;
	}

	/// 
	/// Fixes headers and moves sections.
	/// 
	void FixHeaders();

	/// 
	/// Deletes a section.
	/// 
	virtual void DeleteSection(_In_ WORD wIndex);

	/// 
	/// Overwrites a section with new data.
	/// 
	void OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes);
	
	/// 
	/// Inserts a new section.
	/// 
	void InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header);
	
	/// 
	/// Finds the section containing the raw address.
	/// Returns `_UI16_MAX` if not found.
	/// 
	WORD FindSectionByRaw(_In_ DWORD dwRaw);

	/// 
	/// Removes the DOS stub.
	/// 
	void StripDosStub();
	
	/// 
	/// Gets import tables.
	/// 
	IAT_ENTRY* GetIAT();
	
	/// 
	/// Removes PE overlay.
	/// 
	void DiscardOverlay();
	
	/// 
	/// Gets the offset for the overlay, or 0 if no overlay.
	/// 
	DWORD GetOverlayOffset();
	
	/// 
	/// Finds the section containing the RVA.
	/// Returns `_UI16_MAX` if not found.
	/// 
	WORD FindSectionByRVA(_In_ DWORD dwRVA);

	/// 
	/// Translates a runtime offset to a file offset.
	/// 
	DWORD RVAToRaw(_In_ DWORD dwRVA);

	/// 
	/// Translates a file offset to a runtime offset.
	/// 
	DWORD RawToRVA(_In_ DWORD dwRaw);

	/// 
	/// Formats and writes PE to disk.
	/// 
	bool ProduceBinary(_In_ HANDLE hFile);

	/// 
	/// Formats and writes PE to disk.
	/// 
	bool ProduceBinary(_In_ char* sName);

	/// 
	/// Gets RVAs of exported functions.
	/// 
	Vector<DWORD> GetExportedFunctionRVAs();
	
	/// 
	/// Gets names of exported functions.
	/// 
	Vector<char*> GetExportedFunctionNames();
	
	/// 
	/// Gets list of imported DLLs.
	/// 
	Vector<IMAGE_IMPORT_DESCRIPTOR> GetImportedDLLs();
	
	/// 
	/// Reads string at RVA (because `ReadRVA<char*>` does not work).
	/// 
	char* ReadRVAString(_In_ DWORD dwRVA);

	/// 
	/// Gets list of addresses that get relocated.
	/// 
	Vector<DWORD> GetRelocations();
};