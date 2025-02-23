#include "pe.hpp"

PE::PE(_In_ char* sFileName) {
	if (!sFileName) {
		return;
	}

	HANDLE hFile = CreateFileA(sFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		Status = NoFile;
		return;
	}
	ParseFile(hFile);
	CloseHandle(hFile);
}

PE::PE(_In_ HANDLE hFile) {
	ParseFile(hFile);
}

PE::PE() {}

PE::~PE() {
	while (SectionData.Size()) {
		Buffer data = SectionData.Pop();
		data.Release();
	}
	SectionData.Release();
	SectionHeaders.Release();
	DosStub.Release();
	Overlay.Release();
	OverlayOffset = 0;
	Status = NotSet;
}

PE::PE(_In_ PE* pOther) {
	Status = pOther->Status;
	DosHeader = pOther->DosHeader;
	NTHeaders = pOther->NTHeaders;
	DosStub.Allocate(pOther->DosStub.u64Size);
	memcpy(DosStub.pBytes, pOther->DosStub.pBytes, DosStub.u64Size);
	SectionHeaders.raw.Allocate(pOther->SectionHeaders.raw.u64Size);
	SectionHeaders.nItems = pOther->SectionHeaders.nItems;
	memcpy(SectionHeaders.raw.pBytes, pOther->SectionHeaders.raw.pBytes, SectionHeaders.raw.u64Size);
	for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
		Buffer buf = { 0 };
		if (pOther->SectionData[i].u64Size) {
			buf.Allocate(pOther->SectionData[i].u64Size);
			memcpy(buf.pBytes, pOther->SectionData[i].pBytes, buf.u64Size);
		}
		SectionData.Push(buf);
	}
}

bool PE::ParseFile(_In_ HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		Status = NotSet;
		return false;
	}

	// Read bytes
	size_t szBytes = GetFileSize(hFile, NULL);
	BYTE* pBytes = reinterpret_cast<BYTE*>(malloc(szBytes));
	if (!szBytes || !pBytes || !ReadFile(hFile, pBytes, szBytes, NULL, NULL)) {
		Status = NoFile;
		return false;;
	}

	// DOS header
	memcpy(&DosHeader, pBytes, sizeof(IMAGE_DOS_HEADER));
	if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}

	// DOS stub
	DosStub.Allocate(DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));
	if (DosStub.u64Size) memcpy(DosStub.pBytes, pBytes + sizeof(IMAGE_DOS_HEADER), DosStub.u64Size);

	// NT headers
	memcpy(&NTHeaders, pBytes + DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	if (NTHeaders.Signature != IMAGE_NT_SIGNATURE) {
		Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}
	
	// Validate architecture
	if (NTHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		Status = Unsupported;
		free(pBytes);
		szBytes = 0;
		return false;
	} else if (NTHeaders.OptionalHeader.Magic != 0x20B) {
		Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}

	if (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - NTHeaders.OptionalHeader.NumberOfRvaAndSizes)
		memset(&NTHeaders.OptionalHeader.DataDirectory[NTHeaders.OptionalHeader.NumberOfRvaAndSizes], 0, sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - NTHeaders.OptionalHeader.NumberOfRvaAndSizes));

	SectionHeaders.raw.Allocate(sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections);
	SectionHeaders.nItems = NTHeaders.FileHeader.NumberOfSections;
	memcpy(SectionHeaders.raw.pBytes, pBytes + DosHeader.e_lfanew + NTHeaders.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4, SectionHeaders.raw.u64Size);
	
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		Buffer buf = { 0 };
		buf.Allocate(SectionHeaders[i].SizeOfRawData);
		if (buf.u64Size) memcpy(buf.pBytes, pBytes + SectionHeaders[i].PointerToRawData, buf.u64Size);
		SectionData.Push(buf);
	}

	// Overlay
	OverlayOffset = SectionHeaders[SectionHeaders.Size() - 1].PointerToRawData + SectionHeaders[SectionHeaders.Size() - 1].SizeOfRawData;
	Overlay.Allocate(szBytes - OverlayOffset);
	if (Overlay.u64Size) {
		memcpy(Overlay.pBytes, pBytes + szBytes - Overlay.u64Size, Overlay.u64Size);
	} else {
		OverlayOffset = 0;
	}

	Status = Normal;
	free(pBytes);
	szBytes = 0;
	return true;
}


/***** GET FUNCTIONS *****/

Vector<IMAGE_IMPORT_DESCRIPTOR> PE::GetImportedDLLs() {
	Vector<IMAGE_IMPORT_DESCRIPTOR> ret;
	ret.bCannotBeReleased = true;
	if (Status || !NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress || !NTHeaders.OptionalHeader.DataDirectory[1].Size) return ret;
	Buffer buf = { 0 };
	IMAGE_SECTION_HEADER Header;
	{
		WORD i = FindSectionByRVA(NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress);
		buf = SectionData[i];
		Header = SectionHeaders[i];
		if (!buf.pBytes || !buf.u64Size || NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress + NTHeaders.OptionalHeader.DataDirectory[1].Size > Header.VirtualAddress + Header.Misc.VirtualSize) return ret;
	}

	ret.raw.pBytes = buf.pBytes + NTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress - Header.VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR* pTable = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ret.raw.pBytes);
	IMAGE_IMPORT_DESCRIPTOR zero = { 0 };
	for (int i = 0; NTHeaders.OptionalHeader.DataDirectory[1].Size >= i * sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
		if (!memcmp(&zero, &pTable[i], sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;
		ret.nItems++;
		ret.raw.u64Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return ret;
}

WORD PE::FindSectionByRaw(_In_ DWORD dwRaw) {
	if (Status || dwRaw >= OverlayOffset)
		return _UI16_MAX;

	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (SectionHeaders[i].PointerToRawData && SectionHeaders[i].VirtualAddress && SectionHeaders[i].PointerToRawData <= dwRaw && SectionHeaders[i].SizeOfRawData >= dwRaw) {
			return i;
		}
	}

	return _UI16_MAX;
}

WORD PE::FindSectionByRVA(_In_ DWORD dwRVA) {
	if (Status)
		return _UI16_MAX;

	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (SectionHeaders[i].VirtualAddress && SectionHeaders[i].VirtualAddress <= dwRVA && SectionHeaders[i].VirtualAddress + SectionHeaders[i].Misc.VirtualSize >= dwRVA) {
			return i;
		}
	}

	return _UI16_MAX;
}

DWORD PE::RVAToRaw(_In_ DWORD dwRVA) {
	if (Status)
		return 0;

	WORD wIndex = FindSectionByRVA(dwRVA);
	if (wIndex >= SectionHeaders.Size()) return 0;
	return SectionHeaders[wIndex].PointerToRawData + (dwRVA - SectionHeaders[wIndex].VirtualAddress);
}

DWORD PE::RawToRVA(_In_ DWORD dwRaw) {
	if (Status || dwRaw >= OverlayOffset)
		return 0;

	WORD wIndex = FindSectionByRaw(dwRaw);
	if (wIndex >= SectionHeaders.Size()) return 0;
	return SectionHeaders[wIndex].VirtualAddress + (dwRaw - SectionHeaders[wIndex].PointerToRawData);
}

uint64_t* PE::GetTLSCallbacks() {
	if (Status)
		return NULL;

	// Get directory
	IMAGE_DATA_DIRECTORY TLSDataDir = NTHeaders.OptionalHeader.DataDirectory[9];
	if (!TLSDataDir.VirtualAddress)
		return NULL;

	// Getting TLS callback array
	IMAGE_TLS_DIRECTORY64 dir = ReadRVA<IMAGE_TLS_DIRECTORY64>(TLSDataDir.VirtualAddress);
	WORD wIndex = FindSectionByRVA(dir.AddressOfCallBacks - NTHeaders.OptionalHeader.ImageBase);
	if (wIndex >= SectionHeaders.Size()) return NULL;
	return reinterpret_cast<uint64_t*>(SectionData[wIndex].pBytes + dir.AddressOfCallBacks - NTHeaders.OptionalHeader.ImageBase - SectionHeaders[wIndex].VirtualAddress);
}

IAT_ENTRY* PE::GetIAT() {
	IMAGE_DATA_DIRECTORY IATDir = NTHeaders.OptionalHeader.DataDirectory[1];
	if (!IATDir.VirtualAddress || !IATDir.Size) return NULL;
	WORD i = FindSectionByRVA(IATDir.VirtualAddress);
	if (i >= SectionHeaders.Size()) return NULL;
	return reinterpret_cast<IAT_ENTRY*>(SectionData[i].pBytes + (IATDir.VirtualAddress - SectionHeaders[i].VirtualAddress));
}

void PE::StripDosStub() {
	DosStub.Release();
}

void PE::RebaseImage(_In_ uint64_t u64NewBase) {
	if (!(NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		Vector<DWORD> Relocs = GetRelocations();
		for (int i = 0; i < Relocs.Size(); i++) {
			WriteRVA<uint64_t>(Relocs[i], ReadRVA<uint64_t>(Relocs[i]) - NTHeaders.OptionalHeader.ImageBase + u64NewBase);
		}
		Relocs.Release();
	}
	NTHeaders.OptionalHeader.ImageBase = u64NewBase;
}

void PE::DeleteSection(_In_ WORD wIndex) {
	// Check valid index
	if (Status || wIndex >= SectionHeaders.Size())
		return;

	// Delete header
	NTHeaders.FileHeader.NumberOfSections--;
	SectionHeaders.Remove(wIndex);

	// Delete data (if any)
	SectionData[wIndex].Release();
	SectionData.Remove(wIndex);
}

void PE::OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes) {
	// Check valid index
	if (Status || wIndex >= SectionHeaders.Size())
		return;
	
	Buffer data = { 0 };
	data.pBytes = pBytes;
	data.u64Size = szBytes;
	IMAGE_SECTION_HEADER Header = SectionHeaders[wIndex];
	Header.SizeOfRawData = szBytes;
	SectionData[wIndex].Release();
	SectionData.Replace(wIndex, data);
	SectionHeaders.Replace(wIndex, Header);
}

void PE::InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header) {
	if (Status || wIndex > SectionHeaders.Size())
		return;

	// Insert
	Buffer data = { 0 };
	data.pBytes = pBytes;
	data.u64Size = Header.SizeOfRawData;
	SectionHeaders.Insert(wIndex, Header);
	SectionData.Insert(wIndex, data);
	NTHeaders.FileHeader.NumberOfSections++;
}

void PE::FixHeaders() {
	// DOS Header
	DosHeader.e_magic = IMAGE_DOS_SIGNATURE;
	DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + DosStub.u64Size;

	// Set stuff
	uint64_t Raw = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	uint64_t RVA = Raw;
	IMAGE_SECTION_HEADER Header = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		Raw += (Raw % NTHeaders.OptionalHeader.FileAlignment) ? (NTHeaders.OptionalHeader.FileAlignment - Raw % NTHeaders.OptionalHeader.FileAlignment) : 0;
		RVA += (RVA % NTHeaders.OptionalHeader.SectionAlignment) ? (NTHeaders.OptionalHeader.SectionAlignment - RVA % NTHeaders.OptionalHeader.SectionAlignment) : 0;
		Header = SectionHeaders[i];
		Header.PointerToRawData = Raw;
		Header.VirtualAddress = RVA;
		SectionHeaders.Replace(i, Header);
		RVA += Header.Misc.VirtualSize;
		Raw += Header.SizeOfRawData;
	}

	// File header
	NTHeaders.OptionalHeader.Magic = 0x20B;
	NTHeaders.Signature = IMAGE_NT_SIGNATURE;
	NTHeaders.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	NTHeaders.OptionalHeader.CheckSum = 0;
	NTHeaders.OptionalHeader.SizeOfImage = RVA;
	NTHeaders.OptionalHeader.SizeOfHeaders = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	NTHeaders.OptionalHeader.NumberOfRvaAndSizes = 0x10;
	NTHeaders.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
}

bool PE::ProduceBinary(_In_ HANDLE hFile) {
	// DOS Header
	if (!WriteFile(hFile, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL)) {
		return false;
	}

	// DOS stub
	if (DosStub.pBytes && DosStub.u64Size && !WriteFile(hFile, DosStub.pBytes, DosStub.u64Size, NULL, NULL)) {
		return false;
	}

	// NT Headers (skip DOS stub)
	if (!WriteFile(hFile, &NTHeaders, sizeof(IMAGE_NT_HEADERS64), NULL, NULL)) {
		return false;
	}

	// Section Headers
	if (!WriteFile(hFile, SectionHeaders.raw.pBytes, SectionHeaders.Size() * sizeof(IMAGE_SECTION_HEADER), NULL, NULL)) {
		return false;
	}

	// Section Data
	DWORD dwCurrentAddress = DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;
	BYTE* pZeros = NULL;
	for (WORD i = 0; i < SectionHeaders.Size(); i++) {
		if (!SectionHeaders[i].PointerToRawData) continue;

		// Padding
		if (dwCurrentAddress < SectionHeaders[i].PointerToRawData) {
			pZeros = reinterpret_cast<BYTE*>(calloc(SectionHeaders[i].PointerToRawData - dwCurrentAddress, 1));
			if (!pZeros || !WriteFile(hFile, pZeros, SectionHeaders[i].PointerToRawData - dwCurrentAddress, NULL, NULL)) {
				if (pZeros) free(pZeros);
				return false;
			}
			free(pZeros);
			dwCurrentAddress += SectionHeaders[i].PointerToRawData - dwCurrentAddress;
		} else if (dwCurrentAddress > SectionHeaders[i].PointerToRawData) {
			return false;
		}
		
		// Write actual data (if any)
		if (SectionHeaders[i].SizeOfRawData) {
			if (!WriteFile(hFile, SectionData[i].pBytes, SectionHeaders[i].SizeOfRawData, NULL, NULL)) {
				return false;
			}
			dwCurrentAddress += SectionHeaders[i].SizeOfRawData;
		}
	}

	// Overlay
	if (Overlay.u64Size && Overlay.pBytes) {
		if (!WriteFile(hFile, Overlay.pBytes, Overlay.u64Size, NULL, NULL)) return false;
	}

	return true;
}

bool PE::ProduceBinary(_In_ char* sName) {
	// Open file
	HANDLE hFile = CreateFileA(sName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		return false;
	}

	bool bRet = ProduceBinary(hFile);

	// Close
	CloseHandle(hFile);
	return bRet;
}

Vector<DWORD> PE::GetExportedFunctionRVAs() {
	// Get export table
	Vector<DWORD> vec;
	vec.bCannotBeReleased = true;
	if (!NTHeaders.OptionalHeader.DataDirectory[0].Size || !NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;
	
	// Copy data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfFunctions);
	if (wContainingSection >= SectionHeaders.Size()) return vec;
	Buffer Data = SectionData[wContainingSection];
	if (!Data.pBytes || !Data.u64Size || SectionHeaders[wContainingSection].SizeOfRawData - (ExportTable.AddressOfFunctions - SectionHeaders[wContainingSection].VirtualAddress) < sizeof(DWORD) * ExportTable.NumberOfFunctions) return vec;
	vec.raw.u64Size = ExportTable.NumberOfFunctions * sizeof(DWORD);
	vec.raw.pBytes = Data.pBytes + ExportTable.AddressOfFunctions - SectionHeaders[wContainingSection].VirtualAddress;
	vec.nItems = ExportTable.NumberOfFunctions;
	return vec;
}

Vector<char*> PE::GetExportedFunctionNames() {
	// Get export table
	Vector<char*> vec;
	if (!NTHeaders.OptionalHeader.DataDirectory[0].Size || !NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;

	// Prepare data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfNames);
	if (wContainingSection >= SectionHeaders.Size()) return vec;
	Buffer Data = SectionData[wContainingSection];
	if (!Data.pBytes || !Data.u64Size) return vec;
	Data.pBytes += ExportTable.AddressOfNames - SectionHeaders[wContainingSection].VirtualAddress;
	Data.u64Size -= (ExportTable.AddressOfNames - SectionHeaders[wContainingSection].VirtualAddress);
	
	// Copy data
	for (int i = 0; Data.u64Size >= sizeof(DWORD) && i < ExportTable.NumberOfNames; i++) {
		vec.Push(ReadRVAString(*(DWORD*)Data.pBytes));
		Data.pBytes += sizeof(DWORD);
		Data.u64Size -= sizeof(DWORD);
	}
	return vec;
}

char* PE::ReadRVAString(_In_ DWORD dwRVA) {
	WORD wIndex = FindSectionByRVA(dwRVA);
	if (wIndex >= SectionHeaders.Size() || !SectionData[wIndex].pBytes || !SectionData[wIndex].u64Size) return NULL;
	return reinterpret_cast<char*>(SectionData[wIndex].pBytes + (dwRVA - SectionHeaders[wIndex].VirtualAddress));
}

void PE::WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData) {
	// Verify stuff
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.FileHeader.NumberOfSections - 1 || !SectionHeaders[wSectionIndex].SizeOfRawData || SectionHeaders[wSectionIndex].VirtualAddress > dwRVA || SectionHeaders[wSectionIndex].VirtualAddress + SectionHeaders[wSectionIndex].SizeOfRawData < dwRVA + szData) {
		return;
	}

	// Write data
	memcpy(SectionData[wSectionIndex].pBytes + (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress), pData, szData);
}

void PE::ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData) {
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.FileHeader.NumberOfSections - 1 || !SectionHeaders[wSectionIndex].SizeOfRawData || SectionHeaders[wSectionIndex].VirtualAddress > dwRVA || SectionHeaders[wSectionIndex].VirtualAddress + SectionHeaders[wSectionIndex].SizeOfRawData < dwRVA + szData) {
		ZeroMemory(pData, szData); // This region is defaulted to zero anyways so �\_(._.)_/�
		return;
	}

	memcpy(pData, SectionData[wSectionIndex].pBytes + (dwRVA - SectionHeaders[wSectionIndex].VirtualAddress), szData);
}

Vector<DWORD> PE::GetRelocations() {
	Vector<DWORD> ret;
	if (Status || !NTHeaders.OptionalHeader.DataDirectory[5].Size || !NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress || NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) return ret;
	
	WORD i;
	Buffer sec = { 0 };
	IMAGE_BASE_RELOCATION* pRelocation;

	i = FindSectionByRVA(NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress);
	sec = SectionData[i];
	if (sec.pBytes && sec.u64Size) {
		sec.pBytes += (NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress - SectionHeaders[i].VirtualAddress);
		sec.u64Size -= (NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress - SectionHeaders[i].VirtualAddress);
		WORD nOff = 0;

		do {
			pRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(sec.pBytes + nOff);
			if (!pRelocation->SizeOfBlock || !pRelocation->VirtualAddress) break;
			for (int j = 0, n = (pRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); j < n; j++) {
				i = *reinterpret_cast<WORD*>(sec.pBytes + nOff + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * j);
				if ((i & 0b1111000000000000) != 0b1010000000000000) continue;
				ret.Push(pRelocation->VirtualAddress + (i & 0b0000111111111111));
			}
			nOff += pRelocation->SizeOfBlock;
		} while (pRelocation->SizeOfBlock && NTHeaders.OptionalHeader.DataDirectory[5].Size > nOff && sec.u64Size > nOff);
	}
	return ret;
}

void PE::DiscardOverlay() {
	OverlayOffset = 0;
	Overlay.Release();
}

DWORD PE::GetOverlayOffset() {
	return OverlayOffset;
}