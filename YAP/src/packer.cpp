#include "packer.hpp"
#include "assembler.hpp"
#include "lzma/Aes.h"
#include "lzma/Sha256.h"

BYTE PartialUnpackingHook[] = {
	0x50,																// push rax
	0x68, 0x00, 0x00, 0x00, 0x00,										// push ID
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// mov rax, ENTRY
	0xFF, 0xE0															// jmp rax
};

enum DecoderInstMnemonic : BYTE {
	DI_XOR,
	DI_NOT,
	DI_NEG,
	//DI_ROR,
	//DI_ROL,
	DI_ADD,
	DI_SUB,
	DI_START
};

struct DecoderInst {
	DecoderInstMnemonic Mnemonic : 3;
	DWORD value;
};

Vector<DecoderInst> DecoderProc;
Vector<uint64_t> TLSCallbacks;
_ShellcodeData ShellcodeData;

// Commonly seen section names
char ValidSectionNames[] = 
	".edata\0\0"
	".idata\0\0"
	".rsrc\0\0\0"
	".pdata\0\0"
	".reloc\0\0"
	".debug\0\0"
	".tls\0\0\0\0"
	".text\0\0\0"
	".data\0\0\0"
	".bss\0\0\0\0"
	".rdata\0\0"
	".xdata\0";

Sha256Digest Sha256Str(_In_ char* pStr) {
	CSha256 sha = { 0 };
	Sha256_Init(&sha);
	Sha256_Update(&sha, (Byte*)pStr, lstrlenA(pStr));
	Sha256Digest ret;
	Sha256_Final(&sha, (Byte*)&ret);
	return ret;
}

Sha256Digest Sha256WStr(_In_ wchar_t* pStr) {
	CSha256 sha = { 0 };
	Sha256_Init(&sha);
	Sha256_Update(&sha, (Byte*)pStr, lstrlenW(pStr) * 2);
	Sha256Digest ret;
	Sha256_Final(&sha, (Byte*)&ret);
	return ret;
}

void* Alloc(ISzAllocPtr p, size_t size) { return HeapAlloc(GetProcessHeap(), 0, size); }
void Free(ISzAllocPtr p, void* mem) { HeapFree(GetProcessHeap(), 0, mem); }
uint64_t compressing = 0;
SRes PackingProgress(ICompressProgressPtr p, UInt64 inSize, UInt64 outSize) {
	Data.fTaskProgress = (float)inSize / (float)compressing;
	return 0;
}

Buffer PackSection(_In_ Buffer SectionData) {
	Buffer data = { 0 };
	data.Allocate(SectionData.u64Size * 1.1 + 0x4000);

	// Gen algorithm
	if (!DecoderProc.Size()) {
		DecoderInst inst;
		inst.Mnemonic = DI_START;
		inst.value = rand() & 0xFF;
		DecoderProc.Push(inst);
		for (int i = 0, n = 10 + (rand() & 15); i < n; i++) {
			inst.Mnemonic = (DecoderInstMnemonic)(rand() % DI_SUB);
			inst.value = rand() & 0xFF;
			DecoderProc.Push(inst);
		}
	}

	// Compress
	CLzmaEncProps props = { 0 };
	props.level = Options.Packing.CompressionLevel;
	props.numThreads = 1;
	props.dictSize = 1 << 24;
	props.lc = 3;
	props.pb = 2;
	props.algo = 1;
	props.fb = 5 + 27 * Options.Packing.CompressionLevel;
	props.btMode = 1;
	props.numHashBytes = 4;
	props.mc = 1 + 0x1C71C71C71C7 * Options.Packing.CompressionLevel;
	ICompressProgress progress = { 0 };
	progress.Progress = PackingProgress;
	ISzAlloc alloc = { 0 };
	alloc.Alloc = Alloc;
	alloc.Free = Free;
	size_t propssz = LZMA_PROPS_SIZE;
	uint64_t OldSize = data.u64Size;
	SRes res = LzmaEncode(data.pBytes, &OldSize, SectionData.pBytes, SectionData.u64Size, &props, ShellcodeData.UnpackData.EncodedProp, &propssz, 0, &progress, &alloc, &alloc);
	if (res != SZ_OK) {
		LOG(Failed, MODULE_PACKER, "Failed to compress data (%d)\n", res);
		data.Release();
		return data;
	}
	data.Allocate(OldSize);

	// Encode (inverse cause yeah)
	BYTE key = DecoderProc[0].value;
	BYTE nextkey = 0;
	for (int i = 0; i < data.u64Size; i++) {
		nextkey = key + data.pBytes[i];
		nextkey ^= data.pBytes[i];
		for (int j = DecoderProc.Size() - 1; j > 0; j--) {
			switch (DecoderProc[j].Mnemonic) {
			case DI_XOR:
				data.pBytes[i] ^= key;
				break;
			case DI_NOT:
				data.pBytes[i] = ~data.pBytes[i];
				break;
			case DI_NEG:
				data.pBytes[i] = ~data.pBytes[i] + 1;
				break;
			case DI_ADD:
				data.pBytes[i] -= key;
				break;
			case DI_SUB:
				data.pBytes[i] += key;
			}
		}
		key = nextkey;
	}

	return data;
}

// rcx = compressed buffer
// rdx = compressed size
// r8  = uncompressed buffer
// r9  = uncompressed buffer size
void GenerateUnpackingAlgorithm(_In_ ProtectedAssembler* pA, _In_ Label Entry) {
	pA->bind(Entry);

	// Labels
	Label LzmaDec_TryDummy = pA->newLabel();
	Label LzmaDec_DecodeReal = pA->newLabel();
	Label LzmaDec_DecodeToDic = pA->newLabel();
	Label LzmaDecode = pA->newLabel();
	Label _rcx = pA->newLabel();
	Label _rdx = pA->newLabel();

	// Data
	Label _skipdata = pA->newLabel();
	pA->mov(ptr(_rcx), rcx);
	pA->mov(ptr(_rdx), rdx);
	pA->jmp(_skipdata);
	Label destLen = pA->newLabel();
	pA->bind(destLen);
	pA->dq(rand64());
	Label srcLen = pA->newLabel();
	pA->bind(srcLen);
	pA->dq(0);
	Label propData = pA->newLabel();
	pA->bind(propData);
	pA->embed(ShellcodeData.UnpackData.EncodedProp, sizeof(ShellcodeData.UnpackData.EncodedProp));
	Label alloc = pA->newLabel();
	pA->bind(alloc);
	pA->dq(rand64());
	pA->dq(rand64());
	Label status = pA->newLabel();
	pA->bind(status);
	pA->dq(rand64());

	// Allocate
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);
	Label ptr_HeapAlloc = pA->newLabel();
	pA->bind(ptr_HeapAlloc);
	pA->dq(rand64());
	Label Mem_alloc = pA->newLabel();
	pA->bind(Mem_alloc);
	pA->mov(r8, rdx);
	pA->mov(edx, 0);
	pA->mov(rcx, PEB);
	pA->mov(rcx, ptr(rcx, 0x30));
	pA->push(rsi);
	pA->push(rbx);
	pA->call(ptr(ptr_HeapAlloc));
	pA->add(rsp, 0x10);
	pA->ret();

	// Free
	Label ptr_HeapFree = pA->newLabel();
	pA->bind(ptr_HeapFree);
	pA->dq(rand64());
	Label Mem_free = pA->newLabel();
	pA->bind(Mem_free);
	pA->mov(r8, rdx);
	pA->mov(edx, 0);
	pA->mov(rcx, PEB);
	pA->mov(rcx, ptr(rcx, 0x30));
	pA->push(rsi);
	pA->push(rbx);
	pA->call(ptr(ptr_HeapFree));
	pA->add(rsp, 0x10);
	pA->ret();

	// More data
	Label NTD = pA->newLabel();
	pA->bind(NTD);
	pA->embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
	Label HF = pA->newLabel();
	pA->bind(HF);
	pA->embed(&Sha256Str("RtlFreeHeap"), sizeof(Sha256Digest));
	Label HA = pA->newLabel();
	pA->bind(HA);
	pA->embed(&Sha256Str("RtlAllocateHeap"), sizeof(Sha256Digest));

	// Do the thingy
	pA->bind(_skipdata);

	// Decode
	Label dcd_loop = pA->newLabel();
	pA->push(rcx);
	pA->push(rdx);
	pA->mov(al, DecoderProc[0].value);
	pA->bind(dcd_loop);
	for (int i = 1, n = DecoderProc.Size(); i < n; i++) {
		switch (DecoderProc[i].Mnemonic) {
		case DI_XOR:
			pA->xor_(byte_ptr(rcx), al);
			break;
		case DI_NOT:
			pA->not_(byte_ptr(rcx));
			break;
		case DI_NEG:
			pA->neg(byte_ptr(rcx));
			break;
		case DI_ADD:
			pA->add(byte_ptr(rcx), al);
			break;
		case DI_SUB:
			pA->sub(byte_ptr(rcx), al);
		}
	}
	pA->add(al, byte_ptr(rcx));
	pA->xor_(al, byte_ptr(rcx));
	pA->inc(rcx);
	pA->dec(rdx);
	pA->strict();
	pA->jnz(dcd_loop);
	pA->pop(rdx);
	pA->pop(rcx);

	// Load stuff
	pA->push(r8);
	pA->push(r9);
	pA->push(rdx);
	pA->push(rcx);
	pA->push(r8);
	pA->push(r9);
	pA->lea(rcx, ptr(NTD));
	pA->call(ShellcodeData.Labels.GetModuleHandleW);
	pA->mov(rcx, rax);
	pA->lea(rdx, ptr(HF));
	pA->call(ShellcodeData.Labels.GetProcAddress);
	pA->mov(ptr(ptr_HeapFree), rax);
	pA->lea(rdx, ptr(HA));
	pA->call(ShellcodeData.Labels.GetProcAddress);
	pA->mov(ptr(ptr_HeapAlloc), rax);
	pA->pop(r9);
	pA->pop(rcx);
	pA->pop(r8);
	pA->pop(rdx);

	// Decompress
	pA->mov(ptr(srcLen), rdx);
	pA->mov(ptr(destLen), r9);
	pA->lea(rdx, ptr(alloc));
	pA->lea(r9, ptr(Mem_alloc));
	pA->mov(ptr(rdx), r9);
	pA->lea(r9, ptr(Mem_free));
	pA->mov(ptr(rdx, 0x08), r9);
	pA->mov(ptr(rsp, 0x40), rdx);
	pA->lea(rdx, ptr(status));
	pA->mov(ptr(rsp, 0x38), rdx);
	pA->mov(dword_ptr(rsp, 0x30), 0);
	pA->mov(dword_ptr(rsp, 0x28), 5);
	pA->lea(r9, ptr(propData));
	pA->mov(ptr(rsp, 0x20), r9);
	pA->lea(r9, ptr(srcLen));
	pA->lea(rdx, ptr(destLen));
	pA->call(LzmaDecode);
	pA->mov(rcx, 0);
	pA->xchg(ptr(_rcx), rcx);
	pA->mov(rdx, 0);
	pA->xchg(ptr(_rdx), rdx);
	pA->pop(r9);
	pA->pop(r8);
	
	// re-encode thingy madoodle
	pA->mov(al, DecoderProc[0].value);
	Label enc_loop = pA->newLabel();
	pA->mov(r8b, al);
	pA->bind(enc_loop);
	pA->add(r8b, ptr(rcx));
	pA->xor_(r8b, ptr(rcx));
	for (int i = DecoderProc.Size() - 1; i > 0; i--) {
		switch (DecoderProc[i].Mnemonic) {
		case DI_XOR:
			pA->xor_(byte_ptr(rcx), al);
			break;
		case DI_NOT:
			pA->not_(byte_ptr(rcx));
			break;
		case DI_NEG:
			pA->neg(byte_ptr(rcx));
			break;
		case DI_ADD:
			pA->sub(byte_ptr(rcx), al);
			break;
		case DI_SUB:
			pA->add(byte_ptr(rcx), al);
		}
	}
	pA->mov(al, r8b);
	pA->inc(rcx);
	pA->dec(rdx);
	pA->strict();
	pA->jnz(enc_loop);
	pA->ret();
	
	pA->bind(_rcx);
	pA->dq(0);
	pA->bind(_rdx);
	pA->dq(0);

	// LzmaDecode
	#include "LzmaDecode.raw"

	// LzmaDec_DecodeToDic
	#include "LzmaDec_DecodeToDic.raw"

	// LzmaDec_TryDummy
	#include "LzmaDec_TryDummy.raw"

	// LzmaDec_DecodeReal
	#include "LzmaDec_DecodeReal.raw"
}

Buffer GenerateTLSShellcode(_In_ PE* pPackedBinary, _In_ PE* pOriginal) {
	// Setup
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	a.bMutate = a.bSubstitute = Options.Advanced.bMutateAssembly;
	a.MutationLevel = Options.Packing.MutationLevel;
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);

	Label hidethread;
	if (Options.Packing.bAntiDebug) hidethread = a.newLabel();
	#include "modules/tls.inc"

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseAddress);
	if (a.bFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate TLS shellcode\n");
		return buf;
	}
	buf.Allocate(holder.textSection()->buffer().size());
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	LOG(Success, MODULE_PACKER, "Generated TLS shellcode\n");
	return buf;
}

Buffer GenerateLoaderShellcode(_In_ PE* pOriginal, _In_ PE* pPackedBinary, _In_ Buffer InternalShellcode) {
	// Setup asmjit
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	a.bMutate = a.bSubstitute = Options.Advanced.bMutateAssembly;
	a.MutationLevel = Options.Packing.MutationLevel;
	ShellcodeData.Labels.GetModuleHandleW = a.newLabel();
	ShellcodeData.Labels.GetProcAddress = a.newLabel();
	ShellcodeData.Labels.RtlZeroMemory = a.newLabel();
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);
	CSha256 sha = { 0 };
	Sha256Digest _digest = { 0 };
	Label unpack = a.newLabel();
	Label Sha256_Init = a.newLabel();
	Label Sha256_Update = a.newLabel();
	Label Sha256_Final = a.newLabel();
	Label CompressedSections = a.newLabel();
	Label szshell = a.newLabel();
	Label InternalShell = a.newLabel();
	Label CompressedSizes = a.newLabel();
	Label DecompressedSizes = a.newLabel();
	Label VirtualAddrs = a.newLabel();
	Label hash = a.newLabel();
	Label digest = a.newLabel();

	// Compress
	PE Copied(pOriginal);
	DWORD NumPacked = 0;
	Data.sTask = "Compressing";
	uint64_t DecompressKey = rand64();
	ULONG sz = 0;
	compressing = InternalShellcode.u64Size;
	Buffer CompressedInternal = PackSection(InternalShellcode);
	if (!CompressedInternal.pBytes || !CompressedInternal.u64Size) return buf;
	for (WORD i = 0, n = pOriginal->SectionHeaders.Size(); i < n; i++) {
		Data.fTotalProgress = (float)(i + 1) / (float)(n + 1);
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		
		// Compress data
		compressing = pOriginal->SectionData[i].u64Size;
		Buffer compressed = PackSection(pOriginal->SectionData[i]);
		compressing = 0;
		if (!compressed.pBytes || !compressed.u64Size) return buf;
		LOG(Info_Extended, MODULE_PACKER, "Packed section %.8s (%lld)\n", pOriginal->SectionHeaders[i].Name, (int64_t)compressed.u64Size - pOriginal->SectionHeaders[i].SizeOfRawData);
		if (compressed.u64Size > _UI32_MAX) {
			LOG(Failed, MODULE_PACKER, "Packed section size was too large\n");
			LOG(Info_Extended, MODULE_PACKER, "Size: %p bytes\n", compressed.u64Size);
			LOG(Info_Extended, MODULE_PACKER, "Max size: %p bytes\n", _UI32_MAX);
			return buf;
		}
		Copied.OverwriteSection(i, compressed.pBytes, compressed.u64Size);
		NumPacked++;
	}
	Data.sTask = "Generating loader";
	Data.fTotalProgress = 0.f;
	Data.fTaskProgress = 0.f;

	// Entry point sigs
	if (Options.Packing.bDelayedEntry) {
		for (int i = 0; i < ShellcodeData.EntryOff; i++) a.db(rand() & 255);
	} else {
		switch (Options.Packing.Immitate) {
		case ExeStealth:
			a.db(0xEB);
			a.db(sizeof("ExeStealth V2 Shareware "));
			a.embed("ExeStealth V2 Shareware ", sizeof("ExeStealth V2 Shareware "));
			break;
		}
	}

	// Entry point
	#include "modules/loader.inc"

	// Insert compressed data
	a.bind(CompressedSections);
	for (WORD i = 0, n = pOriginal->NTHeaders.FileHeader.NumberOfSections; i < n; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		Buffer buf = Copied.SectionData[i];
		for (int j = 0; j < buf.u64Size; j++) a.db(buf.pBytes[j]);
	}
	size_t szOffSzShell = 0;
	if (Options.Packing.bAntiDump) {
		a.bind(szshell);
		szOffSzShell = a.offset();
		a.dq(0);
	}
	a.bind(InternalShell);
	a.embed(CompressedInternal.pBytes, CompressedInternal.u64Size);
	
	a.bind(CompressedSizes);
	for (int i = 0; i < Copied.NTHeaders.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq(Copied.SectionHeaders[i].SizeOfRawData ^ DecompressKey);
	}

	a.bind(DecompressedSizes);
	for (int i = 0; i < pOriginal->NTHeaders.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq(pOriginal->SectionHeaders[i].SizeOfRawData ^ DecompressKey);
	}
	
	a.bind(VirtualAddrs);
	for (int i = 0; i < pOriginal->NTHeaders.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq((pOriginal->SectionHeaders[i].VirtualAddress - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders) ^ DecompressKey);
	}

	#include "modules/loader-functions.inc"

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseAddress);
	if (a.bFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate loader shellcode\n");
		return buf;
	}
	ShellcodeData.GetModuleHandleWOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetModuleHandleW);
	ShellcodeData.GetProcAddressOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetProcAddress);
	ShellcodeData.Sha256_InitOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Init);
	ShellcodeData.Sha256_UpdateOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Update);
	ShellcodeData.Sha256_FinalOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Final);
	LOG(Info_Extended, MODULE_PACKER, "Loader code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	buf.Allocate(holder.textSection()->buffer().size());
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	if (Options.Packing.bAntiDump) *reinterpret_cast<QWORD*>(buf.pBytes + szOffSzShell) = buf.u64Size;
	CompressedInternal.Release();
	LOG(Success, MODULE_PACKER, "Generated loader shellcode\n");
	return buf;
}

Buffer GenerateInternalShellcode(_In_ Asm* pOriginal, _In_ Asm* pPackedBinary) {
	// Setup asmjit
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	a.bMutate = a.bSubstitute = Options.Advanced.bMutateAssembly;
	a.MutationLevel = Options.Packing.MutationLevel;
	a.desync();
	Label KERNEL32DLL = a.newLabel();
	Label NTD = a.newLabel();
	Label SIP = a.newLabel();
	Label Sha256_Init = a.newLabel();
	Label Sha256_Update = a.newLabel();
	Label Sha256_Final = a.newLabel();
	Label LoadSegment;
	if (Options.Packing.bPartialUnpacking) LoadSegment = a.newLabel();
	ShellcodeData.Labels.GetModuleHandleW = a.newLabel();
	ShellcodeData.Labels.GetProcAddressByOrdinal = a.newLabel();
	ShellcodeData.Labels.GetProcAddress = a.newLabel();
	ShellcodeData.Labels.RtlZeroMemory = a.newLabel();

	// PEB memory thingy (gs:[0x60])
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);
    Mem TEB = ptr(0x30);
    TEB.setSegment(gs);
	
	Label entrypt = a.newLabel();
	a.bind(entrypt);
	if (Options.Packing.bAntiDump) {
		a.call(ShellcodeData.Labels.RtlZeroMemory);
	}
	a.add(rsp, 0x48);
	a.garbage();

	// Hashing data
	Label skiphash = a.newLabel();
	a.jmp(skiphash);
	Label hash = a.newLabel();
	CSha256 sha = { 0 };
	a.align(AlignMode::kZero, alignof(CSha256));
	a.bind(hash);
	a.embed(&sha, sizeof(CSha256));
	Label digest = a.newLabel();
	Sha256Digest _digest = { 0 };
	a.align(AlignMode::kZero, alignof(Sha256Digest));
	a.bind(digest);
	a.embed(&_digest, sizeof(_digest));
	a.bind(skiphash);

	// Critical marking
	if (Options.Packing.bMarkCritical) {
		#include "modules/critical.inc"
	}

	// Masquerading
	if (Options.Packing.bEnableMasquerade) {
		Label not_found = a.newLabel();
		Label new_buf = a.newLabel();
		BYTE XORKey = rand() & 255;

		#include "modules/masquerading.inc"

		a.bind(new_buf);
		for (int i = 0; i < strlen(Options.Packing.Masquerade); i++) a.db(Options.Packing.Masquerade[i] ^ XORKey);
		a.db(0);

		a.bind(not_found);
	}

	// Sideloading protection
	if (Options.Packing.bMitigateSideloading) {
		#include "modules/anti-sideloading.inc"
	}

	a.garbage();

	// Handle original PE's imports
	Label InternalRelOff;
	Vector<IMAGE_IMPORT_DESCRIPTOR> Imports = pOriginal->GetImportedDLLs();
	if (!Imports.nItems || !Imports.raw.pBytes || !Imports.raw.u64Size) {
		if (Options.Packing.EncodingCounts <= 1) LOG(Warning, MODULE_PACKER, "No imports were found, assuming there are no imported DLLs.\n");
		Label skip = a.newLabel();
		a.jmp(skip);
		a.bind(KERNEL32DLL);
		a.embed(&Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest));
		InternalRelOff = a.newLabel();
		a.bind(InternalRelOff);
		a.dq(ShellcodeData.BaseAddress + pPackedBinary->NTHeaders.OptionalHeader.ImageBase + a.offset());
		a.bind(skip);
		a.lea(rax, ptr(InternalRelOff));
		a.sub(rax, ptr(rax));
		a.mov(ptr(InternalRelOff), rax);
	} else {
		// Skip data
		Label skip = a.newLabel();
		Label begin_module = a.newLabel();
		Label do_name = a.newLabel();
		Label ret = a.newLabel();
		Label dont_ret = a.newLabel();
		a.jmp(skip);

		// data
		a.bind(KERNEL32DLL);
		a.embed(&Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest));

		// Encoded imports
		Vector<size_t> Offsets;
		Label import_array;
		Label jumper_array;
		Label import_handler;
		int nImports = 0;
		if (Options.Packing.bHideIAT) {
			// Labels
			jumper_array = a.newLabel();
			import_array = a.newLabel();
			import_handler = a.newLabel();
			
			// Generate pointer decoding algorithm
			DecoderProc.Release();
			DecoderInst inst;
			for (int i = 0, n = 10 + (rand() & 15); i < n; i++) {
				inst.Mnemonic = (DecoderInstMnemonic)(rand() % DI_SUB);
				inst.value = rand64() & 0xFFFFFFFF;
				DecoderProc.Push(inst);
			}

			// Do jumpers
			for (int j, i = 0; i < Imports.Size(); i++) {
				char* name = pOriginal->ReadRVAString(Imports[i].Name);
				if (!lstrcmpA(name, "yap.dll")) {
					LOG(Info_Extended, MODULE_PACKER, "SDK imported\n");
					ShellcodeData.RequestedFunctions.iIndex = i;
					continue;
				}
				j = 0;
				while (pOriginal->ReadRVA<uint64_t>(Imports[i].OriginalFirstThunk + sizeof(uint64_t) * j)) {
					Offsets.Push(a.offset());
					a.push(nImports);
					a.jmp(import_handler);
					j++;
					nImports++;
				}
			}

			// Jumpers
			a.bind(jumper_array);
			for (int i = 0; i < nImports; i++) {
				a.dq(a.offset() - Offsets[i]);
			}

			// Pointers
			a.bind(import_array);
			a.dq(0, nImports);

			// Import handler
			a.bind(import_handler);
			a.xchg(rax, ptr(rsp));
			a.push(rbx);
			a.lea(rbx, ptr(import_array));
			a.lea(rbx, ptr(rbx, rax, 3));
			a.mov(rax, ptr(rbx));
			a.pop(rbx);
			for (int i = 1, n = DecoderProc.Size(); i < n; i++) {
				switch (DecoderProc[i].Mnemonic) {
				case DI_XOR:
					a.xor_(rax, DecoderProc[i].value);
					break;
				case DI_NOT:
					a.not_(rax);
					break;
				case DI_NEG:
					a.neg(rax);
					break;
				case DI_ADD:
					a.add(rax, DecoderProc[i].value);
					break;
				case DI_SUB:
					a.sub(rax, DecoderProc[i].value);
				}
			}
			a.xchg(ptr(rsp), rax);
			a.ret();
		}

		InternalRelOff = a.newLabel();
		a.bind(InternalRelOff);
		a.dq(ShellcodeData.BaseAddress + pPackedBinary->NTHeaders.OptionalHeader.ImageBase + a.offset());
		
		// Offsets
		Label import_offsets = a.newLabel();
		int64_t offset = a.offset();
		a.bind(import_offsets);
		for (int j, i = 0; i < Imports.Size(); i++) {
			char* name = pOriginal->ReadRVAString(Imports[i].Name);
			if (!Options.Packing.bHideIAT && !_stricmp(name, "yap.dll")) {
				LOG(Info_Extended, MODULE_PACKER, "SDK imported\n");
				ShellcodeData.RequestedFunctions.iIndex = i;
				continue;
			}
			if (i == ShellcodeData.RequestedFunctions.iIndex)
				continue;
			if (Options.Packing.bAPIEmulation) {
				if (!_stricmp(name, "kernel32.dll")) {
					ShellcodeData.RequestedFunctions.iKernel32 = i;
				} else if (!_stricmp(name, "ntdll.dll")) {
					ShellcodeData.RequestedFunctions.iNtDLL = i;
				}
			}
			j = 0;
			a.dd(0);
			while (pOriginal->ReadRVA<uint64_t>(Imports[i].OriginalFirstThunk + sizeof(uint64_t) * j)) {
				a.dd(offset + (pOriginal->NTHeaders.OptionalHeader.SizeOfImage - Imports[i].FirstThunk - sizeof(uint64_t) * j));
				j++;
			}
		}
		a.dd(1);

		Label LLA = a.newLabel();
		a.bind(LLA);
		a.embed(&Sha256Str("LoadLibraryA"), sizeof(Sha256Digest));

		// Embed DLL and import names
		Label import_names = a.newLabel();
		a.bind(import_names);
		for (int j, i = 0; i < Imports.Size(); i++) {
			j = 0;
			IMAGE_IMPORT_DESCRIPTOR descriptor = Imports[i];
			char* name = pOriginal->ReadRVAString(descriptor.Name);
			if (!name) {
				LOG(Failed, MODULE_PACKER, "Failed to read name of imported DLL.\n");
				return buf;
			}
			if (ShellcodeData.RequestedFunctions.iIndex != i) a.embed(name, lstrlenA(name) + 1);
			ZeroMemory(name, lstrlenA(name));
			uint64_t rva = 0;
			while ((rva = pOriginal->ReadRVA<uint64_t>(Imports[i].OriginalFirstThunk + sizeof(uint64_t) * j))) {

#define CHECK_IMPORT(_name) else if (!lstrcmpA(name, #_name)) pRequest = &ShellcodeData.RequestedFunctions._name
				if (rva & 0x8000000000000000) {
					if (ShellcodeData.RequestedFunctions.iIndex != i) {
						LOG(Failed, MODULE_PACKER, "SDK function was imported by ordinal instead of name\n");
						return buf;
					}
					a.db(00);
					a.dw(rva & 0xFFFF);
				} else {
					name = pOriginal->ReadRVAString(rva) + 2;
					if (name == (char*)2) {
						LOG(Failed, MODULE_PACKER, "Failed to read string at 0x%p!\n", pOriginal->NTHeaders.OptionalHeader.ImageBase + rva);
						return buf;
					}
					if (ShellcodeData.RequestedFunctions.iIndex != i) {
						Sha256Digest digest = Sha256Str(name);
						if (Options.Packing.bAPIEmulation && (ShellcodeData.RequestedFunctions.iKernel32 == i || ShellcodeData.RequestedFunctions.iNtDLL == i)) {
							RequestedFunction* pRequest = NULL;
							if (!lstrcmpA(name, "GetCurrentThread")) pRequest = &ShellcodeData.RequestedFunctions.GetCurrentThread;
							CHECK_IMPORT(GetCurrentThreadId);
							CHECK_IMPORT(GetCurrentProcessId);
							CHECK_IMPORT(GetCurrentProcess);
							CHECK_IMPORT(GetTickCount64);
							CHECK_IMPORT(GetStdHandle);
							CHECK_IMPORT(GetLastError);
							CHECK_IMPORT(SetLastError);
							CHECK_IMPORT(GetProcAddress);
							if (pRequest) {
								pRequest->bRequested = true;
								pRequest->dwRVA = descriptor.FirstThunk + sizeof(uint64_t) * j;
								pRequest->Func = a.newLabel();
								ZeroMemory(&digest, sizeof(Sha256Digest));
								LOG(Success, MODULE_PACKER, "Emulating function at 0x%p\n", pOriginal->NTHeaders.OptionalHeader.ImageBase + pRequest->dwRVA);
							}
						}
						a.embed(&digest, sizeof(Sha256Digest));
					} else {
						RequestedFunction* pRequest = NULL;
						
						// Get request name
						if (!lstrcmpA(name, "CheckForDebuggers")) pRequest = &ShellcodeData.RequestedFunctions.CheckForDebuggers;
						CHECK_IMPORT(GetSelf);
						else LOG(Warning, MODULE_PACKER, "Unrecognized SDK import: \'%s\'\n", name);

						// Apply request
						if (pRequest) {
							pRequest->bRequested = true;
							pRequest->dwRVA = descriptor.FirstThunk + sizeof(uint64_t) * j;
							pRequest->Func = a.newLabel();
							LOG(Success, MODULE_PACKER, "Imported SDK function at 0x%p\n", pOriginal->NTHeaders.OptionalHeader.ImageBase + pRequest->dwRVA);
						}
					}
					ZeroMemory(name, lstrlenA(name));
				}
#undef CHECK_IMPORT

				pOriginal->WriteRVA<uint64_t>(Imports[i].OriginalFirstThunk + sizeof(uint64_t) * j, 0);
				j++;
			}
		}
		ZeroMemory(Imports.raw.pBytes, Imports.raw.u64Size);

		#include "modules/importer.inc"
	}

	// Rebase image
	pOriginal->RebaseImage(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders);

	// Handle PEs relocations
	if (!(pOriginal->NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		Vector<DWORD> Relocations = pOriginal->GetRelocations();

		if (Relocations.Size()) {
			Label skipdata = a.newLabel();
			Label data = a.newLabel();
			a.jmp(skipdata);

			a.bind(data);
			for (int i = 0; i < Relocations.Size(); i++) {
				a.dd(Relocations[i]);
			}
			a.dd(0);

			WORD nOff = 0;
			a.bind(skipdata);
			a.mov(rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders);
			a.mov(rax, ptr(InternalRelOff));
			a.add(rcx, rax);
			a.mov(r8, 0);
			a.lea(r9, ptr(data));
			a.mov(r8d, dword_ptr(r9));

			Label loop = a.newLabel();
			a.bind(loop);
			a.add(ptr(rcx, r8), rax);
			a.add(r9, sizeof(DWORD));
			a.mov(r8d, dword_ptr(r9));
			a.test(r8, r8);
			a.strict();
			a.jnz(loop);
		}

		Buffer zero = { 0 };
		zero.Allocate(pOriginal->NTHeaders.OptionalHeader.DataDirectory[5].Size);
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress, zero.pBytes, zero.u64Size);
		zero.Release();
		pOriginal->NTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress = pOriginal->NTHeaders.OptionalHeader.DataDirectory[5].Size = 0;
	}

	// Load SDK
#define LOAD_IMPORT(name) if (ShellcodeData.RequestedFunctions.name.bRequested) { a.lea(rax, ptr(ShellcodeData.RequestedFunctions.name.Func)); a.mov(rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders + ShellcodeData.RequestedFunctions.name.dwRVA); a.add(rcx, ptr(InternalRelOff)); a.mov(qword_ptr(rcx), rax); }
	LOAD_IMPORT(CheckForDebuggers);
	LOAD_IMPORT(GetSelf);
	LOAD_IMPORT(GetCurrentThread);
	LOAD_IMPORT(GetCurrentThreadId);
	LOAD_IMPORT(GetCurrentProcess);
	LOAD_IMPORT(GetCurrentProcessId);
	LOAD_IMPORT(GetTickCount64);
	LOAD_IMPORT(GetStdHandle);
	LOAD_IMPORT(GetLastError);
	LOAD_IMPORT(SetLastError);
	LOAD_IMPORT(GetProcAddress);
#undef LOAD_IMPORT

	// Mark as loaded
	if (ShellcodeData.bUsingTLSCallbacks) {
		a.mov(cx, 0);
		a.mov(byte_ptr(entrypt), cl);
	}

	// Execute TLS callbacks
	{
		uint64_t* pCallbacks = pOriginal->GetTLSCallbacks();
		for (int i = 0; pCallbacks && pCallbacks[i]; i++) {
			a.mov(rcx, pPackedBinary->NTHeaders.OptionalHeader.ImageBase);
			a.add(rcx, ptr(InternalRelOff));
			a.mov(rdx, DLL_PROCESS_ATTACH);
			a.mov(r8d, 0);
			a.mov(rax, pCallbacks[i]);
			a.add(rax, ptr(InternalRelOff));
			a.call(rax);
			TLSCallbacks.Push(pCallbacks[i]);
			pCallbacks[i] = 0;
		}

		Buffer zero = { 0 };
		zero.Allocate(pOriginal->NTHeaders.OptionalHeader.DataDirectory[9].Size);
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->NTHeaders.OptionalHeader.DataDirectory[9].VirtualAddress, zero.pBytes, zero.u64Size);
		zero.Release();
		pOriginal->NTHeaders.OptionalHeader.DataDirectory[9].VirtualAddress = pOriginal->NTHeaders.OptionalHeader.DataDirectory[9].Size = 0;
	}

	// Run main entry point (if applicable)
	if (pOriginal->NTHeaders.OptionalHeader.AddressOfEntryPoint) {
		a.mov(rax, pOriginal->NTHeaders.OptionalHeader.AddressOfEntryPoint + ShellcodeData.OldPENewBaseRVA + pPackedBinary->NTHeaders.OptionalHeader.ImageBase - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders);
		a.add(rax, ptr(InternalRelOff));
		a.push(rax);
		a.garbage();
		if (Options.Packing.EncodingCounts > 1) {
			a.xor_(eax, eax);
			a.strict();
		}
		a.ret();
	}

	#include "modules/sdk.inc"

	// Segment unpacker
	Label Unpack;
	if (Options.Packing.bPartialUnpacking) {
		Vector<FunctionRange> FunctionRanges = pOriginal->GetDisassembledFunctionRanges();
		if (FunctionRanges.Size()) {
			// Data
			Vector<Buffer> FunctionBodies;
			Unpack = a.newLabel();
			Label Flag = a.newLabel();
			a.bind(Flag);
			a.db(0);
			Label CurrentlyLoadedSegment = a.newLabel();
			a.bind(CurrentlyLoadedSegment);
			a.dd(_I32_MAX);
			Label PointerArray = a.newLabel();
			a.bind(PointerArray);
			for (int i = 0; i < FunctionRanges.Size(); i++) {
				a.dq(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders + FunctionRanges[i].dwStart, FunctionRanges[i].Entries.Size());
			}
			Label SizeArray = a.newLabel();
			a.bind(SizeArray);
			for (int i = 0; i < FunctionRanges.Size(); i++) {
				a.dd(FunctionRanges[i].dwSize, FunctionRanges[i].Entries.Size());
			}
			Label EntryArray = a.newLabel();
			a.bind(EntryArray);
			for (int i = 0; i < FunctionRanges.Size(); i++) {
				for (int j = 0; j < FunctionRanges[i].Entries.Size(); j++) {
					a.dq(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders + FunctionRanges[i].Entries[j]);
				}
			}
			Label CompressedSizes = a.newLabel();
			a.bind(CompressedSizes);
			Label Compressed = a.newLabel();
			DWORD ID = 0;
			int count = 0;
			for (DWORD i = 0; i < FunctionRanges.Size(); i++) {
				Buffer buf = { 0 };
				buf.Allocate(FunctionRanges[i].dwSize);
				pOriginal->ReadRVA(FunctionRanges[i].dwStart, buf.pBytes, buf.u64Size);
				FunctionBodies.Push(PackSection(buf));
				ZeroMemory(buf.pBytes, buf.u64Size);
				*reinterpret_cast<DWORD*>(PartialUnpackingHook + 2) = ID;
				ID += FunctionRanges[i].Entries.Size();
				for (int j = 0; j < FunctionRanges[i].Entries.Size(); j++) {
					memcpy_s(buf.pBytes + FunctionRanges[i].Entries[j] - FunctionRanges[i].dwStart, buf.u64Size - (FunctionRanges[i].Entries[j] - FunctionRanges[i].dwStart), PartialUnpackingHook, sizeof(PartialUnpackingHook));
				}
				pOriginal->WriteRVA(FunctionRanges[i].dwStart, buf.pBytes, buf.u64Size);
				buf.Release();
				a.dq(FunctionBodies[FunctionBodies.Size() - 1].u64Size, FunctionRanges[i].Entries.Size());
				count += FunctionRanges[i].Entries.Size();
			}

			#include "modules/segment-unpacker.inc"

			a.bind(Compressed);
			for (int i = 0; i < FunctionBodies.Size(); i++) {
				a.embed(FunctionBodies[i].pBytes, FunctionBodies[i].u64Size);
				FunctionBodies[i].Release();
			}
			FunctionBodies.Release();

			GenerateUnpackingAlgorithm(&a, Unpack);
		}
	}

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.BaseAddress);
	if (a.bFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate internal shellcode\n");
		return buf;
	}
	LOG(Info_Extended, MODULE_PACKER, "Internal code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	ShellcodeData.LoadedOffset = holder.labelOffsetFromBase(entrypt) + holder.baseAddress();
	if (holder.hasRelocEntries()) {
		for (int i = 0; i < holder.relocEntries().size(); i++) {
			if (holder.relocEntries()[i]->_relocType == RelocType::kNone) continue;
			ShellcodeData.Relocations.Relocations.Push(holder.baseAddress() + holder.relocEntries()[i]->sourceOffset() - pPackedBinary->NTHeaders.OptionalHeader.ImageBase);
		}
	}

	buf.Allocate(holder.textSection()->buffer().size());
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	LOG(Success, MODULE_PACKER, "Generated internal shellcode\n");
	return buf;
}

bool Pack(_In_ Asm* pOriginal, _Out_ Asm* pPackedBinary) {
	// Argument validation
	if (!pOriginal || !pPackedBinary) {
		LOG(Failed, MODULE_PACKER, "Invalid arguments\n");
		return false;
	}
	if (!(pOriginal->NTHeaders.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) || (pOriginal->NTHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		LOG(Failed, MODULE_PACKER, "Binary must be relocatable to be packed\n");
		return false;
	}

	Data.State = Packing;
	Data.sTask = "Preparing";
	srand(GetTickCount64());

	if (Options.Packing.bAntiDump) {
		ShellcodeData.CarryData.bWasAntiDump = true;
	}

	if (Options.Packing.EncodingCounts > 1) {
#ifdef _DEBUG
		if (Options.Debug.bDisableRelocations) {
			LOG(Failed, MODULE_PACKER, "Relocations must be enabled to pack multiple times\n");
			return false;
		}
#endif
		Options_t OptionsBackup = Options;
		Options.Packing.Message[0] = 0;
		Options.Packing.Immitate = YAP;
		Options.Packing.bAntiDebug = false;
		Options.Packing.bAntiSandbox = false;
		Options.Packing.bAntiVM = false;
		Options.Packing.bAntiDump = false;
		Options.Packing.bDelayedEntry = false;
		Options.Packing.bMitigateSideloading = false;
		Options.Packing.bOnlyLoadMicrosoft = false;
		Asm* dupe = new Asm();
		dupe->Status = Normal;
		Options.Packing.EncodingCounts--;
		if (!Pack(pOriginal, dupe)) {
			LOG(Failed, MODULE_PACKER, "Packing at depth %d failed\n", Options.Packing.EncodingCounts);
			delete dupe;
			return false;
		}
		ZeroMemory(&ShellcodeData, sizeof(_ShellcodeData));
		ShellcodeData.RequestedFunctions.iIndex = -1;
		LOG(Success, MODULE_PACKER, "Packed at depth %d\n", Options.Packing.EncodingCounts);
		Options = OptionsBackup;
		Options.Packing.bPartialUnpacking = false;
		pOriginal = dupe;
	} else {
		AesGenTables();
		Sha256Prepare();
	}

	// Setup DOS header & stub (e_lfanew is managed by PE)
	pPackedBinary->DosStub.Allocate(pOriginal->DosStub.u64Size);
	memcpy(pPackedBinary->DosStub.pBytes, pOriginal->DosStub.pBytes, pOriginal->DosStub.u64Size);
	pPackedBinary->DosHeader.e_magic = IMAGE_DOS_SIGNATURE;
	pPackedBinary->DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + pPackedBinary->DosStub.u64Size;

	// Save resources
	Buffer resources = { 0 };
	if (Options.Packing.bDontCompressRsrc && pOriginal->NTHeaders.OptionalHeader.DataDirectory[2].Size && pOriginal->NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress) {
		IMAGE_DATA_DIRECTORY rsrc = pOriginal->NTHeaders.OptionalHeader.DataDirectory[2];
		IMAGE_SECTION_HEADER Header = pOriginal->SectionHeaders[pOriginal->FindSectionByRVA(rsrc.VirtualAddress)];
		Buffer raw = pOriginal->SectionData[pOriginal->FindSectionByRVA(rsrc.VirtualAddress)];
		if (!raw.pBytes || !raw.u64Size || !Header.PointerToRawData) {
			LOG(Warning, MODULE_PACKER, "A resource section was present, but resources could not be read! (0x%p)\n", pOriginal->NTHeaders.OptionalHeader.ImageBase + rsrc.VirtualAddress);
		} else {
			resources.Allocate(rsrc.Size);
			memcpy(resources.pBytes, raw.pBytes + rsrc.VirtualAddress - Header.VirtualAddress, resources.u64Size);
			ZeroMemory(raw.pBytes + rsrc.VirtualAddress - Header.VirtualAddress, resources.u64Size);
		}
	}

	// NT headers
	bool bIsDLL = pOriginal->NTHeaders.FileHeader.Characteristics & IMAGE_FILE_DLL;
	IMAGE_NT_HEADERS64* pNT = &pPackedBinary->NTHeaders;
	pNT->Signature = IMAGE_NT_SIGNATURE;
	pNT->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	pNT->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
	pNT->FileHeader.Characteristics = (bIsDLL ? IMAGE_FILE_DLL : 0) | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	DEBUG_ONLY(if (Options.Debug.bDisableRelocations) pNT->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED);
	pNT->OptionalHeader.Magic = 0x20B;
	pNT->OptionalHeader.SectionAlignment = 0x1000;
	pNT->OptionalHeader.FileAlignment = 0x200;
	ShellcodeData.ImageBase = pNT->OptionalHeader.ImageBase = pOriginal->NTHeaders.OptionalHeader.ImageBase;
	pNT->OptionalHeader.MajorOperatingSystemVersion = 4;
	pNT->OptionalHeader.MajorSubsystemVersion = 6;
	pNT->OptionalHeader.SizeOfHeaders = pPackedBinary->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * 2;
	pNT->OptionalHeader.Subsystem = pOriginal->NTHeaders.OptionalHeader.Subsystem;
	pNT->OptionalHeader.NumberOfRvaAndSizes = 0x10;
	pNT->OptionalHeader.SizeOfStackReserve = 0x200000;
	pNT->OptionalHeader.SizeOfHeapReserve = 0x100000;
	pNT->OptionalHeader.SizeOfHeapCommit = pNT->OptionalHeader.SizeOfStackCommit = 0x1000;
	if (Options.Packing.Immitate == UPX) {
		pNT->FileHeader.NumberOfSymbols = 0x21585055; // UPX!
		pNT->FileHeader.PointerToSymbolTable = ((Options.Advanced.UPXVersionPatch + 0x30) << 16) | ((Options.Advanced.UPXVersionMinor + 0x30) << 8) | 0x2E;
		pNT->FileHeader.TimeDateStamp = (Options.Advanced.UPXVersionMajor + 0x30) << 24;
	}
	pNT->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	DEBUG_ONLY(if (Options.Debug.bDisableRelocations) pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	// Section header
	IMAGE_SECTION_HEADER SecHeader = { 0 };
	SecHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	SecHeader.VirtualAddress = pNT->OptionalHeader.SizeOfHeaders;
	SecHeader.VirtualAddress += (SecHeader.VirtualAddress % 0x1000) ? 0x1000 - (SecHeader.VirtualAddress % 0x1000) : 0;
	ShellcodeData.OldPENewBaseRVA = SecHeader.VirtualAddress;
	ShellcodeData.BaseAddress = ShellcodeData.OldPENewBaseRVA + pOriginal->NTHeaders.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders;
	ShellcodeData.bUsingTLSCallbacks = Options.Packing.bDelayedEntry || Options.Packing.bAntiDebug || Options.Packing.bAntiPatch || (pOriginal->GetTLSCallbacks() && *pOriginal->GetTLSCallbacks());
	ShellcodeData.EntryOff = 0x30 + rand() & 0xCF;
	Data.sTask = "Generating internal shellcode";
	Buffer Internal = GenerateInternalShellcode(pOriginal, pPackedBinary);
	if (!Internal.u64Size || !Internal.pBytes) return false;
	SecHeader.Misc.VirtualSize = Internal.u64Size + pOriginal->NTHeaders.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders;
	switch (Options.Packing.Immitate) {
	case Themida:
		memcpy(SecHeader.Name, ".themida", 8);
		break;
	case WinLicense:
		memcpy(SecHeader.Name, ".winlice", 8);
		break;
	case UPX:
		memcpy(SecHeader.Name, "UPX0\0\0\0", 8);
		break;
	case MPRESS:
		memcpy(SecHeader.Name, ".MPRESS1", 8);
		break;
	case Enigma:
		memcpy(SecHeader.Name, ".enigma1", 8);
		break;
	default:
		if (Options.Advanced.bTrueRandomSecNames) {
			for (int i = 0; i < 8; i++) {
				SecHeader.Name[i] = rand() & 0xFF;
			}
		} else if (Options.Advanced.bSemiRandomSecNames) {
			memcpy(SecHeader.Name, &ValidSectionNames[(rand() % (sizeof(ValidSectionNames) / 8)) * 8], 8);
		} else {
			memcpy(SecHeader.Name, Options.Advanced.Sec1Name, 8);
		}
	}
	pPackedBinary->InsertSection(0, NULL, SecHeader);
	SecHeader.VirtualAddress += SecHeader.Misc.VirtualSize;
	SecHeader.VirtualAddress += (SecHeader.VirtualAddress % 0x1000) ? 0x1000 - (SecHeader.VirtualAddress % 0x1000) : 0;
	ShellcodeData.BaseAddress = SecHeader.VirtualAddress;
	switch (Options.Packing.Immitate) {
	case Themida:
		memcpy(SecHeader.Name, "Themida", 8);
		break;
	case WinLicense:
		memcpy(SecHeader.Name, "WinLicen", 8);
		break;
	case UPX:
		memcpy(SecHeader.Name, "UPX1\0\0\0", 8);
		break;
	case MPRESS:
		memcpy(SecHeader.Name, ".MPRESS2", 8);
		break;
	case Enigma:
		memcpy(SecHeader.Name, ".enigma2", 8);
		break;
	default:
		if (Options.Advanced.bTrueRandomSecNames) {
			for (int i = 0; i < 8; i++) {
				SecHeader.Name[i] = rand() & 0xFF;
			}
		} else if (Options.Advanced.bSemiRandomSecNames) {
			memcpy(SecHeader.Name, &ValidSectionNames[(rand() % (sizeof(ValidSectionNames) / 8)) * 8], 8);
		} else {
			memcpy(SecHeader.Name, Options.Advanced.Sec2Name, 8);
		}
	}
	pNT->OptionalHeader.AddressOfEntryPoint = SecHeader.VirtualAddress;

	// Get shellcode
	Data.sTask = "Generating loader";
	Buffer shell = GenerateLoaderShellcode(pOriginal, pPackedBinary, Internal);
	if (Options.Packing.bAntiPatch) {
		CSha256 sha = { 0 };
		Sha256_Init(&sha);
		Sha256_Update(&sha, shell.pBytes, shell.u64Size);
		Sha256_Final(&sha, (Byte*)&ShellcodeData.AntiPatchData.LoaderHash);
	}
	Internal.Release();
	if (!shell.pBytes || !shell.u64Size) return false;

	// TLS callback
	IMAGE_TLS_DIRECTORY64 TLSDataDir = { 0 };
	int nTLSEntries = 0;
	if (ShellcodeData.bUsingTLSCallbacks) {
		// Gen num of TLS
		Data.sTask = "Generating TLS data";
		int nFalseEntries = 0;
		nTLSEntries = 1;
		if (Options.Packing.bAntiDebug) {
			nFalseEntries = 3 + rand() % 5;
			nTLSEntries = nFalseEntries + 1;
		}

		pNT->OptionalHeader.DataDirectory[9].Size = sizeof(IMAGE_TLS_DIRECTORY64);
		pNT->OptionalHeader.DataDirectory[9].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;
		ShellcodeData.BaseAddress = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_TLS_DIRECTORY64) + sizeof(uint64_t) * (nTLSEntries + 1);
		Buffer TLSCode = GenerateTLSShellcode(pPackedBinary, pOriginal);
		if (!TLSCode.u64Size || !TLSCode.pBytes) {
			LOG(Failed, MODULE_PACKER, "Failed to generate TLS shellcode!\n");
			return false;
		}
		TLSDataDir.AddressOfCallBacks = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_TLS_DIRECTORY64) + pPackedBinary->NTHeaders.OptionalHeader.ImageBase;
		TLSDataDir.AddressOfIndex = TLSDataDir.StartAddressOfRawData = TLSDataDir.AddressOfCallBacks + sizeof(uint64_t) * nTLSEntries;
		TLSDataDir.EndAddressOfRawData = TLSDataDir.StartAddressOfRawData + sizeof(uint64_t) * nTLSEntries;
		shell.Allocate(shell.u64Size + sizeof(uint64_t) * (nTLSEntries + 1) + sizeof(IMAGE_TLS_DIRECTORY64) + TLSCode.u64Size);
		memcpy(shell.pBytes + shell.u64Size - (sizeof(uint64_t) * (nFalseEntries + 2) + sizeof(IMAGE_TLS_DIRECTORY64) + TLSCode.u64Size), &TLSDataDir, sizeof(IMAGE_TLS_DIRECTORY64));
		memcpy(shell.pBytes + shell.u64Size - TLSCode.u64Size, TLSCode.pBytes, TLSCode.u64Size);
		uint64_t* pEntries = reinterpret_cast<uint64_t*>(shell.pBytes + shell.u64Size - (sizeof(uint64_t) * (nTLSEntries + 1) + TLSCode.u64Size));
		pEntries[1 + nFalseEntries] = 0;
		pEntries[0] = SecHeader.VirtualAddress + shell.u64Size - TLSCode.u64Size + pPackedBinary->NTHeaders.OptionalHeader.ImageBase;
		for (int i = 1; i < nTLSEntries; i++) {
			pEntries[i] = pPackedBinary->NTHeaders.OptionalHeader.ImageBase + SecHeader.VirtualAddress + shell.u64Size + resources.u64Size + pOriginal->NTHeaders.OptionalHeader.DataDirectory[0].Size + 0x10000 + rand();
		}

		TLSCode.Release();
	}

	// Relocations
	Data.sTask = "Finalizing";
#ifdef _DEBUG
	if (!Options.Debug.bDisableRelocations) {
#endif
		Vector<DWORD> Relocations;
		if (ShellcodeData.bUsingTLSCallbacks) {
			Relocations.Push(pNT->OptionalHeader.DataDirectory[9].VirtualAddress);
			Relocations.Push(pNT->OptionalHeader.DataDirectory[9].VirtualAddress + 0x08);
			Relocations.Push(pNT->OptionalHeader.DataDirectory[9].VirtualAddress + 0x10);
			Relocations.Push(pNT->OptionalHeader.DataDirectory[9].VirtualAddress + 0x18);
			for (int i = 0; i < nTLSEntries; i++) {
				Relocations.Push(TLSDataDir.AddressOfCallBacks - pPackedBinary->NTHeaders.OptionalHeader.ImageBase + sizeof(uint64_t) * i);
			}
		}
		Buffer reloc = GenerateRelocSection(Relocations);
		pNT->OptionalHeader.DataDirectory[5].Size = reloc.u64Size;
		pNT->OptionalHeader.DataDirectory[5].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;
		shell.Merge(reloc);
		Relocations.Release();
#ifdef _DEBUG
	}
#endif

	// Resources
	if (Options.Packing.bDontCompressRsrc && resources.pBytes && resources.u64Size) {
		pPackedBinary->NTHeaders.OptionalHeader.DataDirectory[2].Size = resources.u64Size;
		pPackedBinary->NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;

		// Translate addresses
		Vector<DWORD> Offsets;
		Offsets.Push(0);
		IMAGE_RESOURCE_DIRECTORY* pDir;
		IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntry;
		do {
			pDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(resources.pBytes + Offsets.Pop());
			pEntry = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(reinterpret_cast<BYTE*>(pDir) + sizeof(IMAGE_RESOURCE_DIRECTORY));
			pDir->TimeDateStamp = 0;
			for (int i = 0; i < pDir->NumberOfNamedEntries + pDir->NumberOfIdEntries; i++) {
				if (pEntry[i].DataIsDirectory) {
					Offsets.Push(pEntry[i].OffsetToDirectory);
				} else {
					IMAGE_RESOURCE_DATA_ENTRY* pResource = reinterpret_cast<IMAGE_RESOURCE_DATA_ENTRY*>(resources.pBytes + pEntry[i].OffsetToData);
					pResource->OffsetToData += pPackedBinary->NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress - pOriginal->NTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress;
				}
			}
		} while (Offsets.Size());

		shell.Merge(resources);
	}

	// Exports
	if (pOriginal->NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress && pOriginal->NTHeaders.OptionalHeader.DataDirectory[0].Size) {
		IMAGE_EXPORT_DIRECTORY Exports = { 0 };
		IMAGE_EXPORT_DIRECTORY OriginalExports = pOriginal->ReadRVA<IMAGE_EXPORT_DIRECTORY>(pOriginal->NTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
		Vector<DWORD> exports = pOriginal->GetExportedFunctionRVAs();
		Vector<char*> names = pOriginal->GetExportedFunctionNames();
		pNT->OptionalHeader.DataDirectory[0].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;

		Exports.Base = OriginalExports.Base;
		Exports.NumberOfFunctions = exports.Size();
		Exports.NumberOfNames = names.Size();
		Exports.AddressOfFunctions = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_EXPORT_DIRECTORY);
		Exports.AddressOfNames = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_EXPORT_DIRECTORY) + sizeof(DWORD) * Exports.NumberOfFunctions;
		Exports.AddressOfNameOrdinals = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_EXPORT_DIRECTORY) + sizeof(DWORD) * (Exports.NumberOfFunctions + Exports.NumberOfNames);
		pNT->OptionalHeader.DataDirectory[0].Size = sizeof(IMAGE_EXPORT_DIRECTORY) + sizeof(DWORD) * (Exports.NumberOfFunctions + Exports.NumberOfNames) + sizeof(WORD) * Exports.NumberOfNames;
		shell.Allocate(shell.u64Size + sizeof(IMAGE_EXPORT_DIRECTORY));
		memcpy(shell.pBytes + shell.u64Size - sizeof(IMAGE_EXPORT_DIRECTORY), &Exports, sizeof(IMAGE_EXPORT_DIRECTORY));

		// Export RVAs
		shell.Allocate(shell.u64Size + exports.Size() * sizeof(DWORD));
		for (int i = 0; i < exports.Size(); i++) {
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (exports.Size() - i)) = exports[i] + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.OptionalHeader.SizeOfHeaders;
		}

		// Export names
		shell.Allocate(shell.u64Size + names.Size() * sizeof(DWORD));
		DWORD rva = Exports.AddressOfNameOrdinals + sizeof(WORD) * names.Size();
		for (int i = 0; i < names.Size(); i++) {
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (names.Size() - i)) = rva;
			rva += lstrlenA(names[i]) + 1;
		}

		// Export ordinals
		shell.Allocate(shell.u64Size + names.Size() * sizeof(WORD));
		for (WORD i = 0; i < names.Size(); i++) {
			*reinterpret_cast<WORD*>(shell.pBytes + shell.u64Size - sizeof(WORD) * (names.Size() - i)) = i;
		}

		// Export names
		for (int i = 0; i < names.Size(); i++) {
			int len = lstrlenA(names[i]) + 1;
			shell.Allocate(shell.u64Size + len);
			memcpy(shell.pBytes + shell.u64Size - len, names[i], len);
			pNT->OptionalHeader.DataDirectory[0].Size += len;
		}
		names.Release();
	}

	// Modify section
	SecHeader.PointerToRawData = pNT->OptionalHeader.SizeOfHeaders;
	SecHeader.PointerToRawData += (SecHeader.PointerToRawData % 0x200) ? 0x200 - (SecHeader.PointerToRawData % 0x200) : 0;
	SecHeader.SizeOfRawData = SecHeader.Misc.VirtualSize = shell.u64Size;
	pPackedBinary->InsertSection(pNT->FileHeader.NumberOfSections, shell.pBytes, SecHeader);
	pNT->OptionalHeader.SizeOfImage = SecHeader.VirtualAddress + shell.u64Size;
	pNT->OptionalHeader.SizeOfImage += (pNT->OptionalHeader.SizeOfImage % 0x1000) ? 0x1000 - (pNT->OptionalHeader.SizeOfImage % 0x1000) : 0;
	if (Options.Packing.bDelayedEntry) pPackedBinary->NTHeaders.OptionalHeader.AddressOfEntryPoint = pPackedBinary->SectionHeaders[0].VirtualAddress;

	// MPRESS stuff
	if (Options.Packing.Immitate == MPRESS) {
		memcpy(((BYTE*)&pPackedBinary->DosHeader) + 0x2E, "Win64 .EXE.\r\n", 13);
	}

	// Fake data
	if (Options.Advanced.bFakeSymbols && Options.Packing.Immitate != UPX) {
		pNT->FileHeader.PointerToSymbolTable = SecHeader.PointerToRawData + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) + sizeof(IMAGE_DEBUG_DIRECTORY);
		pNT->FileHeader.NumberOfSymbols = rand();
	}
	pPackedBinary->FixHeaders();
	
	// Signature
	if (Options.Packing.bAntiPatch) {
		CSha256 hash = { 0 };
		Sha256Digest Digest = { 0 };
		Sha256_Init(&hash);
		Sha256_Update(&hash, (Byte*)&pPackedBinary->DosHeader, sizeof(IMAGE_DOS_HEADER));
		Sha256_Update(&hash, pPackedBinary->DosStub.pBytes, pPackedBinary->DosStub.u64Size);
		Sha256_Update(&hash, (Byte*)&pPackedBinary->NTHeaders, sizeof(IMAGE_NT_HEADERS64));
		Sha256_Final(&hash, (Byte*)&Digest);
		pPackedBinary->WriteRVA<Sha256Digest>(pPackedBinary->GetTLSCallbacks()[0] - pPackedBinary->NTHeaders.OptionalHeader.ImageBase + ShellcodeData.AntiPatchData.dwOffHeaderSum, Digest);
	}

	// Finalize
	if (Options.Packing.EncodingCounts > 1) {
		delete pOriginal;
	}
	pPackedBinary->Status = Normal;
	Data.State = Idle;
	Data.sTask = NULL;
	Data.fTaskProgress = 0.f;
	Data.fTotalProgress = 0.f;
	return true;
}