#include "pe.hpp"

PE::PE(_In_ char* sFileName) {
	if (!sFileName) {
		return;
	}

	HANDLE hFile = CreateFileA(sFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		this->Status = NoFile;
		return;
	}
	this->ParseFile(hFile);
	CloseHandle(hFile);
}

PE::PE(_In_ HANDLE hFile) {
	this->ParseFile(hFile);
}

PE::PE(_In_ bool x86) {
	this->x86 = x86;
}

PE::~PE() {
	if (pSectionData && false) {
		for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
			if (pSectionData[i])
				free(pSectionData[i]);
		}
		free(pSectionData);
	}
	if (pSectionHeaders)
		free(pSectionHeaders);
	if (DosStub.pBytes && DosStub.u64Size) {
		free(DosStub.pBytes);
		DosStub.pBytes = reinterpret_cast<BYTE*>(DosStub.u64Size = 0);
	}
	if (Overlay.pBytes) {
		free(Overlay.pBytes);
		Overlay.pBytes = 0;
		Overlay.u64Size = 0;
	}
	OverlayOffset = 0;
	Status = NotSet;
}

PE::PE(_In_ PE* pOther) {
	Status = pOther->Status;
	x86 = pOther->x86;
	DosHeader = pOther->DosHeader;
	NTHeaders = pOther->NTHeaders;
	DosStub = pOther->DosStub;
	DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(DosStub.u64Size));
	memcpy(DosStub.pBytes, pOther->DosStub.pBytes, DosStub.u64Size);
	pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER)));
	memcpy(pSectionHeaders, pOther->pSectionHeaders, NTHeaders.x64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	pSectionData = reinterpret_cast<BYTE**>(malloc(NTHeaders.x64.FileHeader.NumberOfSections * sizeof(BYTE*)));
	for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (pSectionHeaders[i].SizeOfRawData) {
			pSectionData[i] = reinterpret_cast<BYTE*>(malloc(pSectionHeaders[i].SizeOfRawData));
			memcpy(pSectionData[i], pOther->pSectionData[i], pSectionHeaders[i].SizeOfRawData);
		} else {
			pSectionData[i] = NULL;
		}
	}
}

bool PE::ParseFile(_In_ HANDLE hFile) {
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		this->Status = NotSet;
		return false;
	}

	// Read bytes
	size_t szBytes = GetFileSize(hFile, NULL);
	BYTE* pBytes = reinterpret_cast<BYTE*>(malloc(szBytes));
	if (!szBytes || !pBytes || !ReadFile(hFile, pBytes, szBytes, NULL, NULL)) {
		this->Status = NoFile;
		return false;;
	}

	// DOS header
	memcpy(&this->DosHeader, pBytes, sizeof(IMAGE_DOS_HEADER));
	if (this->DosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		this->Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}

	// DOS stub
	DosStub.u64Size = DosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER);
	if (DosStub.u64Size) DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(DosStub.u64Size));
	memcpy(DosStub.pBytes, pBytes + sizeof(IMAGE_DOS_HEADER), DosStub.u64Size);

	// NT headers
	memcpy(&this->NTHeaders.x86, pBytes + this->DosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	if (this->NTHeaders.x64.Signature != IMAGE_NT_SIGNATURE) {
		this->Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}
	
	// Validate architecture
	if (this->NTHeaders.x64.FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
		this->x86 = true;
		if (this->NTHeaders.x86.OptionalHeader.Magic != 0x10B) {
			this->Status = NotPE;
			free(pBytes);
			szBytes = 0;
			return false;
		}
	} else if (this->NTHeaders.x64.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
		this->Status = Unsupported;
		free(pBytes);
		szBytes = 0;
		return false;
	} else if (this->NTHeaders.x64.OptionalHeader.Magic != 0x20B) {
		this->Status = NotPE;
		free(pBytes);
		szBytes = 0;
		return false;
	}

	if (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - this->NTHeaders.x64.OptionalHeader.NumberOfRvaAndSizes)
		memset(&this->NTHeaders.x64.OptionalHeader.DataDirectory[this->NTHeaders.x64.OptionalHeader.NumberOfRvaAndSizes], 0, sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES -
			this->NTHeaders.x64.OptionalHeader.NumberOfRvaAndSizes));

	this->pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(sizeof(IMAGE_SECTION_HEADER) * this->NTHeaders.x64.FileHeader.NumberOfSections));
	memcpy(this->pSectionHeaders, pBytes + this->DosHeader.e_lfanew + this->NTHeaders.x64.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4, sizeof(IMAGE_SECTION_HEADER) *
		this->NTHeaders.x64.FileHeader.NumberOfSections);
	this->pSectionData = reinterpret_cast<BYTE**>(malloc(sizeof(BYTE*) * this->NTHeaders.x64.FileHeader.NumberOfSections));
	
	for (int i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (this->pSectionHeaders[i].SizeOfRawData) {
			pSectionData[i] = reinterpret_cast<BYTE*>(malloc(this->pSectionHeaders[i].SizeOfRawData));
			memcpy(pSectionData[i], pBytes + this->pSectionHeaders[i].PointerToRawData, this->pSectionHeaders[i].SizeOfRawData);
		} else {
			pSectionData[i] = NULL;
		}
	}

	// Overlay
	OverlayOffset = pSectionHeaders[NTHeaders.x64.FileHeader.NumberOfSections - 1].PointerToRawData + pSectionHeaders[NTHeaders.x64.FileHeader.NumberOfSections - 1].SizeOfRawData;
	Overlay.u64Size = szBytes - OverlayOffset;
	if (Overlay.u64Size) {
		Overlay.pBytes = reinterpret_cast<BYTE*>(malloc(Overlay.u64Size));
		memcpy(Overlay.pBytes, pBytes + szBytes - Overlay.u64Size, Overlay.u64Size);
	} else {
		OverlayOffset = 0;
	}

	Status = PEStatus_t::Normal;
	free(pBytes);
	szBytes = 0;
	return true;
}


/***** GET FUNCTIONS *****/

Vector<IMAGE_IMPORT_DESCRIPTOR> PE::GetImportedDLLs() {
	Vector<IMAGE_IMPORT_DESCRIPTOR> ret;
	ret.bCannotBeReleased = true;
	if (Status || !NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress || !NTHeaders.x64.OptionalHeader.DataDirectory[1].Size) return ret;
	Buffer buf = { 0 };
	IMAGE_SECTION_HEADER* pHeader;
	{
		WORD i = FindSectionByRVA(NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress);
		buf = GetSectionBytes(i);
		pHeader = GetSectionHeader(i);
		if (!pHeader || !buf.pBytes || !buf.u64Size || NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress + NTHeaders.x64.OptionalHeader.DataDirectory[1].Size > pHeader->VirtualAddress + pHeader->Misc.VirtualSize) return ret;
	}

	ret.raw.pBytes = buf.pBytes + NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress - pHeader->VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR* pTable = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ret.raw.pBytes);
	IMAGE_IMPORT_DESCRIPTOR zero = { 0 };
	for (int i = 0; NTHeaders.x64.OptionalHeader.DataDirectory[1].Size >= i * sizeof(IMAGE_IMPORT_DESCRIPTOR); i++) {
		if (!memcmp(&zero, &pTable[i], sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;
		ret.nItems++;
		ret.raw.u64Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}
	return ret;
}

IMAGE_DOS_HEADER* PE::GetDosHeader() {
	return &this->DosHeader;
}

ComboNTHeaders* PE::GetNtHeaders() {
	return &this->NTHeaders;
}

IMAGE_SECTION_HEADER* PE::GetSectionHeader(_In_opt_ char* sName) {
	if (this->Status)
		return NULL;

	if (!sName)
		return this->pSectionHeaders;

	return this->GetSectionHeader(this->FindSection(sName));
}

Buffer PE::GetSectionBytes(_In_ char* sName) {
	return this->GetSectionBytes(this->FindSection(sName));
}

ZydisMachineMode PE::GetMachine() {
	return this->x86 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32 : ZYDIS_MACHINE_MODE_LONG_64;
}

WORD PE::FindSectionByRaw(_In_ DWORD dwRaw) {
	if (Status || dwRaw >= OverlayOffset)
		return _UI16_MAX;

	for (WORD i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (this->pSectionHeaders[i].PointerToRawData && this->pSectionHeaders[i].VirtualAddress && this->pSectionHeaders[i].PointerToRawData <= dwRaw && this->pSectionHeaders[i].SizeOfRawData >= dwRaw) {
			return i;
		}
	}

	return _UI16_MAX;
}

WORD PE::FindSectionByRVA(_In_ DWORD dwRVA) {
	if (this->Status)
		return _UI16_MAX;

	for (WORD i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (//this->pSectionHeaders[i].PointerToRawData && 
			this->pSectionHeaders[i].VirtualAddress && this->pSectionHeaders[i].VirtualAddress <= dwRVA && this->pSectionHeaders[i].VirtualAddress + this->pSectionHeaders[i].Misc.VirtualSize >= dwRVA) {
			return i;
		}
	}

	return _UI16_MAX;
}

DWORD PE::RVAToRaw(_In_ DWORD dwRVA) {
	if (Status)
		return 0;

	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRVA(dwRVA));

	if (pHeader)
		return pHeader->PointerToRawData + (dwRVA - pHeader->VirtualAddress);

	return 0;
}

DWORD PE::RawToRVA(_In_ DWORD dwRaw) {
	if (Status)
		return 0;
	
	if (dwRaw >= OverlayOffset) return 0;

	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRaw(dwRaw));

	if (pHeader)
		return pHeader->VirtualAddress + (dwRaw - pHeader->PointerToRawData);

	return 0;
}

uint64_t* PE::GetTLSCallbacks() {
	if (Status)
		return NULL;

	// Get directory
	IMAGE_DATA_DIRECTORY TLSDataDir = GetNtHeaders()->x64.OptionalHeader.DataDirectory[9];
	if (!TLSDataDir.VirtualAddress)
		return NULL;

	// Getting TLS callback array
	IMAGE_TLS_DIRECTORY64 dir = ReadRVA<IMAGE_TLS_DIRECTORY64>(TLSDataDir.VirtualAddress);
	Buffer TLSData = GetSectionBytes(FindSectionByRVA(dir.AddressOfCallBacks - GetBaseAddress()));
	IMAGE_SECTION_HEADER* pTLSSecHeader = GetSectionHeader(FindSectionByRVA(dir.AddressOfCallBacks - GetBaseAddress()));
	return reinterpret_cast<uint64_t*>(TLSData.pBytes + dir.AddressOfCallBacks - GetBaseAddress() - pTLSSecHeader->VirtualAddress);
}

PEStatus_t PE::GetStatus() {
	return Status;
}

Buffer PE::GetSectionBytes(_In_ WORD wIndex) {
	Buffer Buf = { 0 };
	if (this->Status || wIndex > this->NTHeaders.x64.FileHeader.NumberOfSections - 1) {
		return Buf;
	}

	Buf.pBytes = this->pSectionData[wIndex];
	Buf.u64Size = this->pSectionHeaders[wIndex].SizeOfRawData;
	return Buf;
}

Buffer* PE::GetDosStub() {
	return &DosStub;
}

IAT_ENTRY* PE::GetIAT() {
	IMAGE_DATA_DIRECTORY IATDir = GetNtHeaders()->x64.OptionalHeader.DataDirectory[1];
	if (!IATDir.VirtualAddress || !IATDir.Size)
		return NULL;
	WORD i = FindSectionByRVA(IATDir.VirtualAddress);
	if (i == _UI16_MAX)
		return NULL;
	return reinterpret_cast<IAT_ENTRY*>(GetSectionBytes(i).pBytes + (IATDir.VirtualAddress - GetSectionHeader(i)->VirtualAddress));
}

void PE::StripDosStub() {
	if (DosStub.pBytes && DosStub.u64Size) {
		free(DosStub.pBytes);
		DosStub.pBytes = reinterpret_cast<BYTE*>(DosStub.u64Size = 0);
	}
}

void PE::RebaseImage(_In_ uint64_t u64NewBase) {
	if (!(NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		IMAGE_DATA_DIRECTORY reloc;
		WORD i;
		Buffer sec = { 0 };
		IMAGE_BASE_RELOCATION relocation;
		DWORD rva;

		reloc = NTHeaders.x64.OptionalHeader.DataDirectory[5];
		i = FindSectionByRVA(reloc.VirtualAddress);
		sec = GetSectionBytes(i);
		if (sec.pBytes && sec.u64Size) {

			sec.pBytes += (reloc.VirtualAddress - GetSectionHeader(i)->VirtualAddress);
			sec.u64Size -= (reloc.VirtualAddress - GetSectionHeader(i)->VirtualAddress);

			WORD nOff = 0;
			do {
				relocation = *reinterpret_cast<IMAGE_BASE_RELOCATION*>(sec.pBytes + nOff);
				if (!relocation.SizeOfBlock || !relocation.VirtualAddress) break;
				for (int j = 0, n = (relocation.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); j < n; j++) {
					i = *reinterpret_cast<WORD*>(sec.pBytes + nOff + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * j);
					if ((i & 0b1111000000000000) != 0b1010000000000000) continue;
					rva = relocation.VirtualAddress + (i & 0b0000111111111111);
					uint64_t value = ReadRVA<uint64_t>(rva);
					value -= NTHeaders.x64.OptionalHeader.ImageBase;
					value += u64NewBase;
					WriteRVA<uint64_t>(rva, value);
				}
				nOff += relocation.SizeOfBlock;
			} while (relocation.SizeOfBlock && reloc.Size > nOff);
		}
	}
	NTHeaders.x64.OptionalHeader.ImageBase = u64NewBase;
}

IMAGE_SECTION_HEADER* PE::GetSectionHeader(_In_ WORD wIndex) {
	if (this->Status || wIndex >= this->NTHeaders.x64.FileHeader.NumberOfSections) {
		return NULL;
	}
	return &this->pSectionHeaders[wIndex];
}

IMAGE_SECTION_HEADER* PE::GetSectionHeaders() {
	return this->pSectionHeaders;
}

uint64_t PE::GetBaseAddress() {
	return this->x86 ? this->NTHeaders.x86.OptionalHeader.ImageBase : this->NTHeaders.x64.OptionalHeader.ImageBase;
}

void PE::DeleteSection(_In_ WORD wIndex) {
	// Check valid index
	if (this->Status || wIndex >= this->NTHeaders.x64.FileHeader.NumberOfSections) {
		return;
	}

	// Delete header
	this->NTHeaders.x64.FileHeader.NumberOfSections--;
	IMAGE_SECTION_HEADER* pNewSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(malloc(sizeof(IMAGE_SECTION_HEADER) * this->NTHeaders.x64.FileHeader.NumberOfSections));
	memcpy(pNewSectionHeaders, this->pSectionHeaders, sizeof(IMAGE_SECTION_HEADER) * wIndex);
	memcpy(&pNewSectionHeaders[wIndex], &this->pSectionHeaders[wIndex + 1], sizeof(IMAGE_SECTION_HEADER) * (this->NTHeaders.x64.FileHeader.NumberOfSections - wIndex));
	free(this->pSectionHeaders);
	this->pSectionHeaders = pNewSectionHeaders;

	// Delete data (if any)
	if (this->pSectionData[wIndex]) {
		free(this->pSectionData[wIndex]);
	}
	BYTE** pNewSectionData = reinterpret_cast<BYTE**>(malloc(sizeof(BYTE*) * this->NTHeaders.x64.FileHeader.NumberOfSections));
	memcpy(pNewSectionData, this->pSectionData, sizeof(BYTE*) * wIndex);
	memcpy(&pNewSectionData[wIndex], &this->pSectionData[wIndex + 1], sizeof(BYTE*) * (this->NTHeaders.x64.FileHeader.NumberOfSections - wIndex));
	free(this->pSectionData);
	this->pSectionData = pNewSectionData;
}

void PE::OverwriteSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_opt_ size_t szBytes) {
	// Check valid index
	if (this->Status || wIndex >= this->NTHeaders.x64.FileHeader.NumberOfSections) {
		return;
	}
	
	if (this->pSectionData[wIndex]) {
		free(this->pSectionData[wIndex]);
	}
	this->pSectionHeaders[wIndex].SizeOfRawData = szBytes;
	this->pSectionData[wIndex] = pBytes;
}

void PE::InsertSection(_In_ WORD wIndex, _In_opt_ BYTE* pBytes, _In_ IMAGE_SECTION_HEADER Header) {
	if (wIndex > NTHeaders.x64.FileHeader.NumberOfSections) {
		return;
	}

	// Resize data
	NTHeaders.x64.FileHeader.NumberOfSections++;
	pSectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(realloc(pSectionHeaders, sizeof(IMAGE_SECTION_HEADER) * NTHeaders.x64.FileHeader.NumberOfSections));
	pSectionData = reinterpret_cast<BYTE**>(realloc(pSectionData, sizeof(BYTE*) * NTHeaders.x64.FileHeader.NumberOfSections));

	// Shift existing data
	for (int i = NTHeaders.x64.FileHeader.NumberOfSections - 1; i > wIndex; i--) {
		pSectionHeaders[i] = pSectionHeaders[i - 1];
		pSectionData[i] = pSectionData[i - 1];
	}

	// Insert
	pSectionHeaders[wIndex] = Header;
	pSectionData[wIndex] = pBytes;
}

WORD PE::FindSection(_In_ char* sName) {
	if (this->Status)
		return _UI16_MAX;

	for (WORD i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!strcmp(reinterpret_cast<char*>(this->pSectionHeaders[i].Name), sName)) {
			return i;
		}
	}
	
	return _UI16_MAX;
}

void PE::FixHeaders() {
	// DOS Header
	DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + DosStub.u64Size;

	// Raw addresses
	DWORD Raw = NTHeaders.x64.OptionalHeader.SizeOfHeaders;
	for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		Raw += (Raw % NTHeaders.x64.OptionalHeader.FileAlignment) ? NTHeaders.x64.OptionalHeader.FileAlignment - (Raw % NTHeaders.x64.OptionalHeader.FileAlignment) : 0;
		pSectionHeaders[i].PointerToRawData = Raw;
		Raw += pSectionHeaders[i].SizeOfRawData;
	}
}

void PE::MoveSections() {
	uint64_t u64RawAddress = this->DosHeader.e_lfanew + (this->x86 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64)) + sizeof(IMAGE_SECTION_HEADER) * this->NTHeaders.x64.FileHeader.NumberOfSections;
	uint64_t u64RVA = u64RawAddress;

	for (WORD i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		// Alignment
		u64RawAddress += (u64RawAddress % this->NTHeaders.x64.OptionalHeader.FileAlignment) ? (this->NTHeaders.x64.OptionalHeader.FileAlignment - u64RawAddress % this->NTHeaders.x64.OptionalHeader.FileAlignment) : 0;
		u64RVA += (u64RVA % this->NTHeaders.x64.OptionalHeader.SectionAlignment) ? (this->NTHeaders.x64.OptionalHeader.SectionAlignment - u64RVA % this->NTHeaders.x64.OptionalHeader.SectionAlignment) : 0;

		// Copy addresses
		this->pSectionHeaders[i].VirtualAddress = u64RVA;
		this->pSectionHeaders[i].PointerToRawData = u64RawAddress;

		// Move stuffs
		u64RVA += this->pSectionHeaders[i].Misc.VirtualSize;
		u64RawAddress += this->pSectionHeaders[i].SizeOfRawData;
	}
}

bool PE::ProduceBinary(_In_ HANDLE hFile) {
	// DOS Header
	if (!WriteFile(hFile, &this->DosHeader, sizeof(IMAGE_DOS_HEADER), NULL, NULL)) {
		return false;
	}

	// DOS stub
	if (DosStub.pBytes && DosStub.u64Size && !WriteFile(hFile, DosStub.pBytes, DosStub.u64Size, NULL, NULL)) {
		return false;
	}

	// NT Headers (skip DOS stub)
	if (!WriteFile(hFile, &this->NTHeaders, this->x86 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64), NULL, NULL)) {
		return false;
	}

	// Section Headers
	if (!WriteFile(hFile, this->pSectionHeaders, sizeof(IMAGE_SECTION_HEADER) * this->NTHeaders.x64.FileHeader.NumberOfSections, NULL, NULL)) {
		return false;
	}

	// Section Data
	DWORD dwCurrentAddress = DosHeader.e_lfanew + (this->x86 ? sizeof(IMAGE_NT_HEADERS32) : sizeof(IMAGE_NT_HEADERS64)) + sizeof(IMAGE_SECTION_HEADER) * this->NTHeaders.x64.FileHeader.NumberOfSections;
	BYTE* pZeros = NULL;
	for (WORD i = 0; i < this->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!pSectionHeaders[i].PointerToRawData) continue;

		// Padding
		if (dwCurrentAddress < this->pSectionHeaders[i].PointerToRawData) {
			pZeros = reinterpret_cast<BYTE*>(calloc(this->pSectionHeaders[i].PointerToRawData - dwCurrentAddress, 1));
			if (!pZeros || !WriteFile(hFile, pZeros, this->pSectionHeaders[i].PointerToRawData - dwCurrentAddress, NULL, NULL)) {
				if (pZeros) free(pZeros);
				return false;
			}
			free(pZeros);
			dwCurrentAddress += this->pSectionHeaders[i].PointerToRawData - dwCurrentAddress;
		} else if (dwCurrentAddress > this->pSectionHeaders[i].PointerToRawData) {
			return false;
		}
		
		// Write actual data (if any)
		if (this->pSectionHeaders[i].SizeOfRawData) {
			if (!WriteFile(hFile, this->pSectionData[i], this->pSectionHeaders[i].SizeOfRawData, NULL, NULL)) {
				return false;
			}
			dwCurrentAddress += this->pSectionHeaders[i].SizeOfRawData;
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
	if (!NTHeaders.x64.OptionalHeader.DataDirectory[0].Size || !NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;
	
	// Copy data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfFunctions);
	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(wContainingSection);
	Buffer Data = GetSectionBytes(wContainingSection);
	if (wContainingSection == _UI16_MAX || !pHeader || !Data.pBytes || !Data.u64Size || pHeader->SizeOfRawData - (ExportTable.AddressOfFunctions - pHeader->VirtualAddress) < sizeof(DWORD) * ExportTable.NumberOfFunctions) return vec;
	vec.raw.u64Size = ExportTable.NumberOfFunctions * sizeof(DWORD);
	vec.raw.pBytes = Data.pBytes + ExportTable.AddressOfFunctions - pHeader->VirtualAddress;
	vec.nItems = ExportTable.NumberOfFunctions;
	vec.bCannotBeReleased = true;
	//vec.raw.pBytes = reinterpret_cast<BYTE*>(malloc(vec.raw.u64Size));
	//memcpy(vec.raw.pBytes, Data.pBytes + ExportTable.AddressOfFunctions - pHeader->VirtualAddress, vec.raw.u64Size);
	return vec;
}

Vector<char*> PE::GetExportedFunctionNames() {
	// Get export table
	Vector<char*> vec;
	if (!NTHeaders.x64.OptionalHeader.DataDirectory[0].Size || !NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress) return vec;
	IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!ExportTable.NumberOfFunctions || !ExportTable.AddressOfFunctions || !ExportTable.AddressOfNames) return vec;

	// Prepare data
	WORD wContainingSection = FindSectionByRVA(ExportTable.AddressOfNames);
	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(wContainingSection);
	Buffer Data = GetSectionBytes(wContainingSection);
	if (wContainingSection == _UI16_MAX || !pHeader || !Data.pBytes || !Data.u64Size) return vec;
	Data.pBytes += ExportTable.AddressOfNames - pHeader->VirtualAddress;
	Data.u64Size -= (ExportTable.AddressOfNames - pHeader->VirtualAddress);
	
	// Copy data
	for (int i = 0; Data.u64Size >= sizeof(DWORD) && i < ExportTable.NumberOfNames; i++) {
		vec.Push(ReadRVAString(*(DWORD*)Data.pBytes));
		Data.pBytes += sizeof(DWORD);
		Data.u64Size -= sizeof(DWORD);
	}
	return vec;
}

char* PE::ReadRVAString(_In_ DWORD dwRVA) {
	Buffer buf = GetSectionBytes(FindSectionByRVA(dwRVA));
	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRVA(dwRVA));
	if (!buf.pBytes || !buf.u64Size || !pHeader) return NULL;
	return reinterpret_cast<char*>(buf.pBytes + (dwRVA - pHeader->VirtualAddress));
}

void PE::WriteRVA(_In_ DWORD dwRVA, _In_ void* pData, _In_ size_t szData) {
	// Verify stuff
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.x64.FileHeader.NumberOfSections - 1 || !pSectionHeaders[wSectionIndex].SizeOfRawData || pSectionHeaders[wSectionIndex].VirtualAddress > dwRVA || pSectionHeaders[wSectionIndex].VirtualAddress + pSectionHeaders[wSectionIndex].Misc.VirtualSize < dwRVA + szData) {
		return;
	}

	// Write data
	memcpy(pSectionData[wSectionIndex] + (dwRVA - pSectionHeaders[wSectionIndex].VirtualAddress), pData, szData);
}

void PE::ReadRVA(_In_ DWORD dwRVA, _Out_ void* pData, _In_ size_t szData) {
	WORD wSectionIndex = FindSectionByRVA(dwRVA);
	if (!pData || !szData || wSectionIndex > NTHeaders.x64.FileHeader.NumberOfSections - 1 || !pSectionHeaders[wSectionIndex].SizeOfRawData || pSectionHeaders[wSectionIndex].VirtualAddress > dwRVA ||
		pSectionHeaders[wSectionIndex].VirtualAddress + pSectionHeaders[wSectionIndex].Misc.VirtualSize < dwRVA + szData) {
		ZeroMemory(pData, szData);
		return;
	}

	memcpy(pData, pSectionData[wSectionIndex] + (dwRVA - pSectionHeaders[wSectionIndex].VirtualAddress), szData);
}

Vector<DWORD> PE::GetRelocations() {
	Vector<DWORD> ret;
	if (Status || !NTHeaders.x64.OptionalHeader.DataDirectory[5].Size || !NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress || GetNtHeaders()->x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) return ret;
	
	WORD i;
	Buffer sec = { 0 };
	IMAGE_BASE_RELOCATION* pRelocation;

	i = FindSectionByRVA(NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress);
	sec = GetSectionBytes(i);
	if (sec.pBytes && sec.u64Size) {
		sec.pBytes += (NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress - GetSectionHeader(i)->VirtualAddress);
		sec.u64Size -= (NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress - GetSectionHeader(i)->VirtualAddress);
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
		} while (pRelocation->SizeOfBlock && NTHeaders.x64.OptionalHeader.DataDirectory[5].Size > nOff && sec.u64Size > nOff);
	}
	return ret;
}


Buffer* PE::GetOverlay() {
	return &Overlay;
}

void PE::DiscardOverlay() {
	OverlayOffset = 0;
	if (Overlay.pBytes) free(Overlay.pBytes);
	Overlay.pBytes = 0;
	Overlay.u64Size = 0;
}

DWORD PE::GetOverlayOffset() {
	return OverlayOffset;
}