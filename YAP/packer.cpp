#include "packer.hpp"
#include "assembler.hpp"
#include "lzma/Aes.h"
#include "lzma/Sha256.h"

BYTE PartialUnpackingHook[] = {
	0x50,
	0x68, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xFF, 0xE0
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
bool bAsmJitFailed = false;

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

// Handle AsmJit errors
class AsmJitErrorHandler : public ErrorHandler {
public:
	void handleError(_In_ Error error, _In_ const char* message, _In_ BaseEmitter* emitter) override {
		LOG(Failed, MODULE_PACKER, "AsmJit error: %s\n", message);
		bAsmJitFailed = true;
	}
};

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
SRes PackingProgress(ICompressProgressPtr p, UInt64 inSize, UInt64 outSize) { return 0; }

Buffer PackSection(_In_ Buffer SectionData) {
	Buffer data = { 0 };
	data.u64Size = SectionData.u64Size * 1.1 + 0x4000;
	data.pBytes = reinterpret_cast<BYTE*>(malloc(data.u64Size));

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
	SRes res = LzmaEncode(data.pBytes, &data.u64Size, SectionData.pBytes, SectionData.u64Size, &props, ShellcodeData.UnpackData.EncodedProp, &propssz, 0, &progress, &alloc, &alloc);
	if (res != SZ_OK) {
		LOG(Failed, MODULE_PACKER, "Failed to compress data (%d)\n", res);
		free(data.pBytes);
		data.pBytes = NULL;
		data.u64Size = 0;
		return data;
	}
	data.pBytes = reinterpret_cast<BYTE*>(realloc(data.pBytes, data.u64Size));

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

	// Check if its process start TLS
	Label hidethread;
	if (Options.Packing.bAntiDebug) hidethread = a.newLabel();
	Label _do = a.newLabel();
	a.desync();
	a.desync_mov(rax);
	Label reloc = a.newLabel();
	a.cmp(rdx, 1);
	a.strict();
	a.je(_do);

	// If it's not, call packed binaries TLS callbacks (if unpacked)
	if (TLSCallbacks.Size()) {
		if (Options.Packing.bAntiDebug) {
			Label donthide = a.newLabel();
			a.cmp(rdx, 2);
			a.strict();
			a.jne(donthide);
			a.call(hidethread);
			a.bind(donthide);
		}
		Label isloaded = a.newLabel();
		a.mov(rax, ShellcodeData.LoadedOffset);
		a.add(rax, ptr(reloc));
		a.cmp(byte_ptr(rax), 0);
		a.strict();
		a.jz(isloaded);
		a.ret();
		a.bind(isloaded);
		a.push(r8);
		a.push(rdx);
		a.push(rcx);
		for (int i = 0; i < TLSCallbacks.Size(); i++) {
			a.mov(rax, TLSCallbacks[i]);
			a.add(rax, ptr(reloc));
			a.mov(rcx, qword_ptr(rsp));
			a.mov(rdx, qword_ptr(rsp, 0x08));
			a.mov(r8, qword_ptr(rsp, 0x10));
			a.call(rax);
		}
		TLSCallbacks.Release();
		a.pop(rcx);
		a.pop(rdx);
		a.pop(r8);
	}
	a.mov(rax, 0);
	a.ret();

	// Otherwise do stuff
	a.bind(reloc);
	a.dq(ShellcodeData.BaseAddress + pPackedBinary->GetBaseAddress() + a.offset());
	a.bind(_do);
	a.desync_mov(rdx);
	if (Options.Packing.bAntiDebug) a.call(hidethread);
	a.push(r12);
	a.push(r13);
	a.push(r14);
	a.push(r15);
	a.push(rdi);
	a.push(rsi);
	a.push(rbx);
	a.push(rbp);
	a.lea(rax, ptr(reloc));
	a.sub(rax, ptr(rax));
	a.mov(ptr(reloc), rax);
	if (Options.Packing.bAntiDebug) {
		a.mov(rax, 0);
		a.desync();
		a.mov(rcx, PEB);
		a.mov(al, byte_ptr(rcx, 0x02));
		a.shl(rax, 32);
		a.mov(rdx, 0xBC);
		a.mov(rsi, 0x70);
		a.mov(r8d, dword_ptr(rcx, rdx));
		a.and_(r8, rsi);
		a.xor_(r8, rsi);
		a.strict();
		a.setz(al);
		a.or_(al, byte_ptr(0x7FFE02D4));
		a.mov(rcx, rax);
		for (int i = 0; i < 32; i++) {
			a.shl(rcx, 1);
			a.or_(rcx, rax);
		}
		a.push(rcx);
		a.mov(rcx, 0);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3(); a.block());
		a.popfq();
		a.block();
		a.jz(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress - (rand() & 0xFFFF));
	}
	if (Options.Packing.bAntiPatch) {
		Label hash = a.newLabel();
		Label HeaderDigest = a.newLabel();
		Label LoaderDigest = a.newLabel();
		Label checksigs = a.newLabel();
		a.jmp(checksigs);
		a.garbage();
		a.bind(HeaderDigest);
		ShellcodeData.AntiPatchData.dwOffHeaderSum = a.offset();
		a.db(0, sizeof(Sha256Digest));
		a.bind(hash);
		a.db(0, sizeof(CSha256));
		a.garbage();
		a.bind(LoaderDigest);
		a.embed(&ShellcodeData.AntiPatchData.LoaderHash, sizeof(Sha256Digest));
		a.garbage();

		a.bind(checksigs);
		a.lea(rcx, ptr(hash));
		a.push(rcx);
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.Sha256_InitOff);
		a.mov(rcx, ptr(rsp));
		a.mov(rdx, pPackedBinary->GetBaseAddress());
		a.add(rdx, ptr(reloc));
		a.mov(r8, pPackedBinary->NTHeaders.x64.OptionalHeader.SizeOfHeaders);
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.Sha256_UpdateOff);
		a.pop(rcx);
		a.mov(rdx, rcx);
		a.add(rdx, sizeof(CSha256)); // rdx -> garbage
		a.push(rdx);
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.Sha256_FinalOff);
		a.mov(rcx, ptr(rsp)); // rcx -> rdx
		a.pop(rdx);
		a.sub(rcx, sizeof(Sha256Digest) + sizeof(CSha256)); // rcx -> HeaderDigest
		for (int i = 0; i < sizeof(Sha256Digest) / sizeof(QWORD); i++) {
			a.mov(r8, ptr(rdx));
			a.sub(r8, 8);
			a.sub(ptr(rcx), r8);
			a.add(rdx, ptr(rcx));
			a.add(rcx, ptr(rcx));
		}
		// fuck me (check the thingymadoodle)
	}
	if (Options.Packing.bDelayedEntry) {
		a.mov(rax, pPackedBinary->GetBaseAddress() + pPackedBinary->SectionHeaders[0].VirtualAddress);
		a.add(rax, ptr(reloc));
		if (Options.Packing.bAntiDebug) {
			a.cmp(byte_ptr(rax), 0xCC);
			a.strict();
			a.mov(rcx, 0);
			a.strict();
			a.cmovnz(rcx, rax);
			a.cmp(word_ptr(rax), 0x03CD);
			a.strict();
			a.mov(byte_ptr(rax), 0xC3);
			a.strict();
			a.mov(rax, rcx);
			a.strict();
			a.cmovz(rax, rsp);
			a.call(rax);
			a.mov(byte_ptr(rax), 0x00);
		}
		a.add(rax, 2 * (rand64() % (pPackedBinary->SectionHeaders[0].Misc.VirtualSize / 2)));
		a.mov(word_ptr(rax), 0xB848);
		a.add(rax, 2);
		a.mov(rcx, pPackedBinary->GetBaseAddress() + pPackedBinary->NTHeaders.x64.OptionalHeader.AddressOfEntryPoint + ShellcodeData.EntryOff);
		a.add(rcx, ptr(reloc));
		a.mov(qword_ptr(rax), rcx);
		a.add(rax, 8);
		a.mov(word_ptr(rax), 0xE0FF);
	}
	a.garbage();
	a.pop(rbp);
	a.pop(rbx);
	a.pop(rsi);
	a.pop(rdi);
	a.pop(r15);
	a.pop(r14);
	a.pop(r13);
	a.pop(r12);
	a.mov(rax, 1);
	a.ret();

	if (Options.Packing.bAntiDebug) {
		Label NTD = a.newLabel();
		a.bind(NTD);
		a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
		Label STI = a.newLabel();
		a.bind(STI);
		a.embed(&Sha256Str("NtSetInformationThread"), sizeof(Sha256Digest));
		a.bind(hidethread);
		a.lea(rcx, ptr(NTD));
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.GetModuleHandleWOff);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(STI));
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.GetProcAddressOff);
		a.mov(Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.mov(r8, rsp);
		a.and_(r8, 0b1111);
		a.add(r8, 8);
		a.sub(rsp, r8);
		a.push(r8);
		a.mov(rdx, 17);
		a.mov(r8, 0);
		if (Options.Packing.bDirectSyscalls) {
			Label thingy = a.newLabel();
			a.lea(r9, ptr(thingy));
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.mov(rcx, 0);
			a.strict();
			a.cmovnz(r9, rcx);
			a.jmp(r9);
			a.bind(thingy);
			a.mov(eax, ptr(rax, 4));
			a.mov(r9, 0);
			a.syscall();
		} else {
			a.mov(r9, 0);
			a.call(rax);
		}
		a.pop(r8);
		a.add(rsp, r8);
		a.ret();
	}

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress);
	if (bAsmJitFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate TLS shellcode\n");
		return buf;
	}
	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
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
	Label _entry = a.newLabel();
	Label message = a.newLabel();
	Label ret = a.newLabel();
	Label unpack = a.newLabel();
	Label Sha256_Init = a.newLabel();
	Label Sha256_Update = a.newLabel();
	Label Sha256_Final = a.newLabel();

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
	if (Options.Advanced.bMutateAssembly) {
		a.strict();
		a.jz(_entry);
		a.garbage();
	} else {
		a.jmp(_entry);
	}

	// Data
	if (Options.Packing.Message[0]) {
		a.bind(message);
		a.embed(Options.Packing.Message, lstrlenA(Options.Packing.Message) + 1);
	}
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
	a.bind(ret);
	a.add(rsp, 0x40);
	a.garbage();
	a.ret();

	// Entry point
	a.bind(_entry);
	if (Options.Packing.Message[0]) {
		a.lea(rax, ptr(message));
	}
	a.desync_mov(rax);
	a.garbage();
	a.desync_mov(rdx);
	
	// Get base offset
	Label SkipReloc = a.newLabel();
	a.jmp(SkipReloc);
	Label Reloc = a.newLabel();
	a.bind(Reloc);
	a.dq(ShellcodeData.BaseAddress + a.offset() + pPackedBinary->GetBaseAddress());
	Label NTD = a.newLabel();
	Label SIP = a.newLabel();
	if (Options.Packing.bOnlyLoadMicrosoft) {
		a.bind(NTD);
		a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
		a.bind(SIP);
		a.embed(&Sha256Str("ZwSetInformationProcess"), sizeof(Sha256Digest));
	}
	a.garbage();
	a.bind(SkipReloc);
	a.lea(rax, ptr(Reloc));
	a.sub(rax, ptr(rax));
	a.mov(ptr(Reloc), rax);

	a.sub(rsp, 0x40);
	a.strict();
	a.desync_jnz();

	// Microsoft signing
	if (Options.Packing.bOnlyLoadMicrosoft) {
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(SIP));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		Label skippolicy = a.newLabel();
		if (Options.Advanced.bMutateAssembly) {
			a.strict();
			a.jnz(skippolicy);
		} else {
			a.jmp(skippolicy);
		}
		
		// Data
		Label policy = a.newLabel();
		PROCESS_MITIGATION_POLICY _policy = ProcessSignaturePolicy;
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig_policy = { 0 };
		sig_policy.MicrosoftSignedOnly = 1;
		a.align(AlignMode::kCode, alignof(PROCESS_MITIGATION_POLICY));
		a.bind(policy);
		a.embed(&_policy, sizeof(PROCESS_MITIGATION_POLICY));
		a.align(AlignMode::kZero, alignof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));
		a.embed(&sig_policy, sizeof(PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY));

		a.bind(skippolicy);
		a.mov(Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFF);
		a.mov(edx, 52);
		a.lea(r8, ptr(policy));
		a.mov(r9d, holder.labelOffset(skippolicy) - holder.labelOffset(policy));
		if (Options.Packing.bDirectSyscalls) {
			a.mov(ecx, dword_ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.jnz(ret);
			a.mov(eax, ptr(rax, 4));
			a.syscall();
		} else {
			a.call(rax);
		}
	}

	// Debug
	if (Options.Packing.bAntiDebug) {
		// Setup context
		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;
		
		Label skipdata = a.newLabel();
		a.jmp(skipdata);

		a.align(AlignMode::kCode, alignof(CONTEXT));
		Label Context = a.newLabel();
		a.bind(Context);
		a.embed(&context, sizeof(CONTEXT));
		Label NTD = a.newLabel();
		a.bind(NTD);
		a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
		Label GCT = a.newLabel();
		a.bind(GCT);
		a.embed(&Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest));

		a.bind(skipdata);
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(GCT));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.lea(rdx, ptr(Context));
		a.mov(rsi, rdx);
		if (Options.Packing.bDirectSyscalls) {
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.jnz(ret);
			a.mov(eax, ptr(rax, 4));
			a.syscall();
		} else {
			a.call(rax);
		}
		a.mov(rdx, rsi);
		a.test(rax, rax);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr7)));
		a.and_(rax, 0x20FF);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr6)));
		a.and_(rax, 0x18F);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr0)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr1)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr2)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr3)));
		a.strict();
		a.jnz(ret);
	}

	// VM detection (TODO)
	if (Options.Packing.bAntiVM) {
		a.mov(eax, 1);
		a.cpuid();
		a.bt(ecx, 31);
		a.strict();
		if (!Options.Packing.bAllowHyperV) {
			a.jc(ret);
		} else {
			Label nohv = a.newLabel();
			a.jnc(nohv);
			a.mov(eax, 0x40000000);
			a.cpuid();
			a.cmp(ebx, 0x7263694D);
			a.strict();
			a.jne(ret);
			a.cmp(ecx, 0x666F736F);
			a.strict();
			a.jne(ret);
			a.cmp(edx, 0x76482074);
			a.strict();
			a.jne(ret);
			a.bind(nohv);
		}
	}

	// Wait for cursor activity
	if (Options.Packing.bAntiSandbox) {
		Label _skip = a.newLabel();
		Label USR = a.newLabel();
		Label GCP = a.newLabel();
		Label _KRN = a.newLabel();
		Label SLP = a.newLabel();
		Label PT = a.newLabel();
		Label _loop = a.newLabel();
		Label LLA = a.newLabel();
		a.jmp(_skip);

		a.align(AlignMode::kCode, alignof(LPCSTR));
		a.bind(USR);
		a.embed("USER32.dll", 11);
		a.bind(GCP);
		a.embed(&Sha256Str("GetCursorPos"), sizeof(Sha256Digest));
		a.bind(SLP);
		a.embed(&Sha256Str("Sleep"), sizeof(Sha256Digest));
		a.bind(_KRN);
		a.embed(&Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest));
		a.bind(LLA);
		a.embed(&Sha256Str("LoadLibraryA"), sizeof(Sha256Digest));
		a.align(AlignMode::kCode, 0x10);
		a.bind(PT);
		a.dq(rand64());
		a.dq(rand64());

		a.bind(_skip);
		a.lea(rcx, ptr(_KRN));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.push(rcx);
		a.lea(rdx, ptr(SLP));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r13, rax);
		a.pop(rcx);
		a.lea(rdx, ptr(LLA));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.lea(rcx, ptr(USR));
		a.push(rsi);
		a.push(rbx);
		a.call(rax);
		a.add(rsp, 0x10);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(GCP));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r12, rax);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.lea(rcx, ptr(PT));
		a.sub(rsp, 0x20);
		a.call(r12);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r14, ptr(PT));
		a.bind(_loop);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.mov(ecx, 5);
		a.sub(rsp, 0x20);
		a.call(r13);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.lea(rcx, ptr(PT));
		a.sub(rsp, 0x20);
		a.call(r12);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.test(rax, rax);
		a.strict();
		a.jz(_loop);
		a.cmp(r14, ptr(PT));
		a.strict();
		a.jz(_loop);
	}

	if (Options.Packing.bAntiDump) {
		Label skip = a.newLabel();
		a.jmp(skip);

		Label KRN = a.newLabel();
		a.align(AlignMode::kCode, alignof(DWORD));
		a.bind(KRN);
		a.embed(&Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest));
		Label VRT = a.newLabel();
		a.bind(VRT);
		a.embed(&Sha256Str("VirtualProtect"), sizeof(Sha256Digest));
		
		a.bind(skip);
		a.mov(rax, PEB);
		a.mov(qword_ptr(rax, 0x10), 0);
		a.lea(rcx, ptr(KRN));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(VRT));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, pPackedBinary->GetBaseAddress());
		a.add(rcx, ptr(Reloc));
		a.mov(edx, ptr(rcx, offsetof(IMAGE_DOS_HEADER, e_lfanew)));
		a.add(rdx, rcx);
		a.mov(edx, ptr(rdx, offsetof(IMAGE_NT_HEADERS64, OptionalHeader.SizeOfHeaders)));
		a.push(rdx);
		a.push(rcx);
		a.lea(r9, ptr(KRN));
		a.mov(rsi, rax);
		a.sub(rsp, 0x18);
		a.mov(r8, rsp);
		a.and_(r8, 0b1111);
		a.add(r8, 8);
		a.sub(rsp, r8);
		a.push(r8);
		a.mov(r8, 0x40);
		a.sub(rsp, 0x20);
		a.call(rax);
		a.add(rsp, 0x20);
		a.pop(r8);
		a.add(rsp, r8);
		a.add(rsp, 0x18);
		a.pop(rcx);
		a.pop(rdx);
		a.call(ShellcodeData.Labels.RtlZeroMemory);
	}

	// Load each section
	Label CompressedSections = a.newLabel();
	Label CompressedSizes = a.newLabel();
	Label DecompressedSizes = a.newLabel();
	Label VirtualAddrs = a.newLabel();
	PE Copied(pOriginal);

	DWORD NumPacked = 0;
	for (WORD i = 0, n = pOriginal->SectionHeaders.Size(); i < n; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		
		// Compress data
		Buffer compressed = PackSection(pOriginal->SectionData[i]);
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
	a.mov(rsi, 0);
	a.lea(rcx, ptr(CompressedSections));
	a.mov(rbp, pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA);
	uint64_t DecompressKey = rand64();
	Label decompressloop = a.newLabel();
	a.bind(decompressloop);
	a.mov(rax, DecompressKey);
	a.lea(rdx, ptr(CompressedSizes));
	a.mov(rdx, ptr(rdx, rsi, 3));
	a.xor_(rdx, rax);
	a.lea(r8, ptr(VirtualAddrs));
	a.mov(r8, ptr(r8, rsi, 3));
	a.xor_(r8, rax);
	a.add(r8, rbp);
	a.add(r8, ptr(Reloc));
	a.lea(r9, ptr(DecompressedSizes));
	a.mov(r9, ptr(r9, rsi, 3));
	a.xor_(r9, rax);
	a.mov(rax, 0);
	a.call(unpack);
	a.inc(rsi);
	a.cmp(rsi, NumPacked);
	a.strict();
	a.jne(decompressloop);
	Label InternalShell = a.newLabel();
	ULONG sz = 0;
	Buffer CompressedInternal = PackSection(InternalShellcode);
	if (!CompressedInternal.pBytes || !CompressedInternal.u64Size) return buf;
	a.lea(rcx, ptr(InternalShell));
	a.mov(rdx, CompressedInternal.u64Size);
	a.mov(r8, pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA + pOriginal->NTHeaders.x64.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders);
	a.add(r8, ptr(Reloc));
	a.mov(r9, InternalShellcode.u64Size);
	a.call(unpack);
	
	// Relocation stuff
	a.mov(rax, ptr(Reloc));
	if (ShellcodeData.Relocations.Relocations.Size()) {
		for (int i = 0, n = ShellcodeData.Relocations.Relocations.Size(); i < n; i++) {
			a.mov(r10, pPackedBinary->GetBaseAddress() + ShellcodeData.Relocations.Relocations[i]);
			a.add(r10, rax);
			a.add(ptr(r10), rax);
		}
		ShellcodeData.Relocations.Relocations.Release();
	}
	a.mov(rcx, rax);

	a.desync();
	a.mov(rax, pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA + pOriginal->NTHeaders.x64.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders);
	a.add(rax, rcx);
	Label szshell = a.newLabel();
	if (Options.Packing.bAntiDump) {
		a.lea(rcx, ptr(rip));
		a.sub(rcx, a.offset());
		a.mov(rdx, ptr(szshell));
	}
	DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3(); a.block());
	a.call(rax);
	a.garbage();

	// Insert compressed data
	a.bind(CompressedSections);
	for (WORD i = 0, n = pOriginal->NTHeaders.x64.FileHeader.NumberOfSections; i < n; i++) {
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
	for (int i = 0; i < Copied.NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq(Copied.SectionHeaders[i].SizeOfRawData ^ DecompressKey);
	}

	a.bind(DecompressedSizes);
	for (int i = 0; i < pOriginal->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq(pOriginal->SectionHeaders[i].SizeOfRawData ^ DecompressKey);
	}
	
	a.bind(VirtualAddrs);
	for (int i = 0; i < pOriginal->NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!pOriginal->SectionHeaders[i].Misc.VirtualSize || !pOriginal->SectionHeaders[i].SizeOfRawData) continue;
		a.dq((pOriginal->SectionHeaders[i].VirtualAddress - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders) ^ DecompressKey);
	}

	// GetModuleHandleW
	{
		// Labels
		Label item = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label final_check = a.newLabel();
		Label bad = a.newLabel();
		Label ret_self = a.newLabel();
		a.bind(ShellcodeData.Labels.GetModuleHandleW);

		// Asm
		a.desync();
		a.mov(rax, PEB);
		a.test(rcx, rcx);
		a.strict();
		a.jz(ret_self);
		a.mov(rax, ptr(rax, offsetof(_PEB, Ldr)));
		a.mov(rax, ptr(rax, offsetof(_PEB_LDR_DATA, InMemoryOrderModuleList)));
		a.sub(rax, 0x10);
		a.bind(item);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rax);
		a.push(rcx);
		a.lea(rcx, ptr(hash));
		a.mov(rdx, sizeof(CSha256));
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Init);
		a.pop(rcx);
		a.pop(rax);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.mov(rax, ptr(rax, 0x10));
		a.test(rax, rax);
		a.strict();
		a.jz(bad);
		a.sub(rax, 0x10);
		a.lea(r8, ptr(rax, 0x58));
		a.mov(r9, ptr(r8, 0x08));
		a.test(r9, r9);
		a.strict();
		a.jz(bad);
		a.mov(r10d, 0);
		a.bind(strcmp_loop);
		a.inc(r10);
		a.mov(r11w, word_ptr(r9, r10, 1));
		a.test(r11w, r11w);
		a.strict();
		a.jnz(strcmp_loop);
		a.shl(r10, 1);
		a.push(rax);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rcx);
		a.mov(rdx, r9);
		a.mov(r8, r10);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Update);
		a.lea(rcx, ptr(hash));
		a.lea(rdx, ptr(digest));
		a.call(Sha256_Final);
		a.mov(rax, 0);
		a.pop(rcx);
		a.lea(r11, ptr(digest));
		Label ___skip = a.newLabel();
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.high)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, high.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.low)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, high.low)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.high)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, low.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.low)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, low.low)));
		a.strict();
		a.setne(al);
		a.bind(___skip);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.test(al, al);
		a.strict();
		a.pop(rax);
		a.strict();
		a.jnz(item);
		a.mov(rax, ptr(rax, 0x30));
		a.ret();
		a.bind(bad);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.ret();
		a.bind(ret_self);
		a.mov(rax, ptr(rax, 0x10));
		a.ret();
	}

	// Sha256
	#include "SHA256.raw"

	GenerateUnpackingAlgorithm(&a, unpack);
	DecoderProc.Release();

	// GetProcAddress
	{
		// Labels
		Label loop = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label found = a.newLabel();
		Label bad = a.newLabel();
		Label ret = a.newLabel();
		a.bind(ShellcodeData.Labels.GetProcAddress);
		
		// Asm
		a.desync();
		a.push(r12);
		a.push(r13);
		a.push(r14);
		a.push(rbx);
		a.mov(r12d, 0);
		a.mov(r8d, dword_ptr(rcx, 0x3C));
		a.mov(r8d, dword_ptr(rcx, r8, 0, 0x88));
		a.mov(r9d, dword_ptr(rcx, r8, 0, 0x18));
		a.mov(r10d, dword_ptr(rcx, r8, 0, 0x20));
		a.add(r10, rcx);
		a.mov(r11d, dword_ptr(rcx, r8, 0, 0x24));
		a.add(r11, rcx);
		a.bind(loop);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rdx);
		a.push(rcx);
		a.lea(rcx, ptr(hash));
		a.mov(rdx, sizeof(CSha256));
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Init);
		a.pop(rcx);
		a.pop(rdx);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.cmp(r12, r9);
		a.strict();
		a.je(bad);
		a.mov(r13d, dword_ptr(r10, r12, 2));
		a.inc(r12);
		a.add(r13, rcx);
		a.mov(r14d, 0);
		a.bind(strcmp_loop);
		a.mov(al, byte_ptr(r13, r14));
		a.test(al, al);
		a.strict();
		a.jz(found);
		a.inc(r14);
		a.jmp(strcmp_loop);
		a.bind(found);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rdx);
		a.push(rcx);
		a.mov(rdx, r13);
		a.mov(r8, r14);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Update);
		a.lea(rcx, ptr(hash));
		a.lea(rdx, ptr(digest));
		a.call(Sha256_Final);
		Label ___skip = a.newLabel();
		a.pop(rcx);
		a.pop(rdx);
		a.lea(r11, ptr(digest));
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.high)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, high.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.low)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, high.low)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.high)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, low.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.low)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, low.low)));
		a.strict();
		a.setne(al);
		a.bind(___skip);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.test(al, al);
		a.strict();
		a.jnz(loop);
		a.mov(eax, dword_ptr(rcx, r8, 0, 0x1C));
		a.add(rax, rcx);
		a.dec(r12);
		a.movzx(edx, word_ptr(r11, r12, 1));
		a.mov(eax, dword_ptr(rax, rdx, 2));
		a.add(rax, rcx);
		a.jmp(ret);
		a.bind(bad);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.bind(ret);
		a.pop(rbx);
		a.pop(r14);
		a.pop(r13);
		a.pop(r12);
		a.ret();
	}

	// RtlZeroMemory
	{
		// Labels
		Label loop = a.newLabel();
		a.bind(ShellcodeData.Labels.RtlZeroMemory);

		a.test(rdx, rdx);
		a.strict();
		a.jz(ret);
		a.test(rcx, rcx);
		a.strict();
		a.jz(ret);
		a.mov(al, 0);
		a.bind(loop);
		a.mov(byte_ptr(rcx), al);
		a.inc(rcx);
		a.dec(rdx);
		a.strict();
		a.jnz(loop);
		a.ret();
	}

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress);
	if (bAsmJitFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate loader shellcode\n");
		return buf;
	}
	ShellcodeData.GetModuleHandleWOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetModuleHandleW);
	ShellcodeData.GetProcAddressOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetProcAddress);
	ShellcodeData.Sha256_InitOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Init);
	ShellcodeData.Sha256_UpdateOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Update);
	ShellcodeData.Sha256_FinalOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(Sha256_Final);
	LOG(Info_Extended, MODULE_PACKER, "Loader code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
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
		Label data = a.newLabel();
		Label ret = a.newLabel();
		Label _skip = a.newLabel();
		a.jmp(_skip);

		a.bind(NTD);
		a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
		a.bind(SIP);
		a.embed(&Sha256Str("ZwSetInformationProcess"), sizeof(Sha256Digest));
		a.align(AlignMode::kCode, alignof(BOOL));
		a.bind(data);
		a.dd(1);
		a.bind(ret);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.ret();

		a.bind(_skip);
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(SIP));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFF);
		a.mov(edx, 0x1D);
		a.mov(r9d, 4);
		a.mov(r8, rsp);
		a.and_(r8, 0b1111);
		a.add(r8, 8);
		a.sub(rsp, r8);
		a.push(r8);
		a.lea(r8, ptr(data));
		if (Options.Packing.bDirectSyscalls) {
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.jnz(ret);
			a.mov(eax, ptr(rax, 4));
			a.syscall();
		} else {
			a.call(rax);
		}
		a.pop(r8);
		a.add(rsp, r8);
	}

	// Masquerading
	if (Options.Packing.bEnableMasquerade) {
		Label not_found = a.newLabel();
		Label new_buf = a.newLabel();
		Label copy_byte = a.newLabel();
		Label zero_remainder = a.newLabel();
		BYTE XORKey = rand() & 255;

		// Check buffer size
		a.mov(rax, PEB);
		a.mov(rax, ptr(rax, 0x20));
		a.mov(si, word_ptr(rax, 0x62));
		a.cmp(si, 2 * (lstrlenA(Options.Packing.Masquerade) + 1));
		a.strict();
		a.jle(not_found);

		// Copy string
		a.mov(rcx, ptr(rax, 0x68));
		a.lea(r8, ptr(new_buf));
		a.mov(dx, 0);
		a.mov(rdi, 0);
		a.bind(copy_byte);
		a.mov(dl, byte_ptr(r8, di));
		a.test(dl, dl);
		a.strict();
		a.jz(zero_remainder);
		a.xor_(dl, XORKey);
		a.mov(word_ptr(rcx, di, 1), dx);
		a.inc(di);
		a.cmp(dl, '\\');
		a.strict();
		a.jne(copy_byte);
		a.mov(r9w, di);
		a.shl(r9w, 1);
		a.jmp(copy_byte);

		// Zero the remainder of the buffer
		a.bind(zero_remainder);
		a.lea(rcx, ptr(rcx, di, 1));
		a.movzx(rdx, si);
		a.shl(rdi, 1);
		a.sub(rdx, rdi);
		a.sub(rdx, 2);
		a.push(rax);
		a.push(r9w);
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.mov(r9d, 0);
		a.pop(r9w);
		a.pop(rax);

		// Copy data
		// bx  = Length
		// cx  = MaximumLength
		// rdx = Buffer
		a.mov(bx, 2 * lstrlenA(Options.Packing.Masquerade)); // Get data
		a.mov(cx, 2 * (lstrlenA(Options.Packing.Masquerade) + 1));
		a.mov(rdx, ptr(rax, 0x68));
		a.mov(word_ptr(rax, 0x70), bx); // CommandLine
		a.mov(word_ptr(rax, 0x72), cx);
		a.mov(ptr(rax, 0x78), rdx);
		a.mov(word_ptr(rax, 0xB0), bx); // WindowTitle
		a.mov(word_ptr(rax, 0xB2), cx);
		a.mov(ptr(rax, 0xB8), rdx);
		a.mov(word_ptr(rax, 0x60), bx); // ImagePathName
		a.mov(word_ptr(rax, 0x62), cx);
		a.mov(ptr(rax, 0x68), rdx);
		a.mov(rax, PEB);
		a.mov(rax, ptr(rax, offsetof(_PEB, Ldr)));
		a.mov(rax, ptr(rax, 0x10));
		a.mov(word_ptr(rax, 0x48), bx); // FullDllName
		a.mov(word_ptr(rax, 0x4A), cx);
		a.mov(ptr(rax, 0x50), rdx);
		a.sub(bx, r9w);
		a.sub(cx, r9w);
		a.add(rdx, r9);
		a.mov(word_ptr(rax, 0x58), bx); // BaseDllName
		a.mov(word_ptr(rax, 0x5A), cx);
		a.mov(ptr(rax, 0x60), rdx);
		a.jmp(not_found);

		a.bind(new_buf);
		a.embed(Options.Packing.Masquerade, lstrlenA(Options.Packing.Masquerade) + 1);

		a.bind(not_found);
	}

	// Sideloading protection
	if (Options.Packing.bMitigateSideloading) {
		Label skip = a.newLabel();
		Label ret = a.newLabel();
		a.jmp(skip);

		Label DIR = a.newLabel();
		a.bind(DIR);
		a.embed(&Sha256Str("SetDllDirectoryA"), sizeof(Sha256Digest));
		Label SSP = a.newLabel();
		a.bind(SSP);
		a.embed(&Sha256Str("SetSearchPathMode"), sizeof(Sha256Digest));
		Label ZRO = a.newLabel();
		a.bind(ZRO);
		a.db(0);

		a.bind(skip);
		a.lea(rcx, ptr(KERNEL32DLL));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.mov(rsi, rax);
		a.lea(rdx, ptr(DIR));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.lea(rcx, ptr(ZRO));
		a.sub(rsp, 0x20);
		a.call(rax);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.mov(rcx, rsi);
		a.lea(rdx, ptr(SSP));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.mov(ecx, BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
		a.sub(rsp, 0x20);
		a.call(rax);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		
		a.bind(ret);
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
		a.dq(ShellcodeData.BaseAddress + pPackedBinary->GetBaseAddress() + a.offset());
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
		a.dq(ShellcodeData.BaseAddress + pPackedBinary->GetBaseAddress() + a.offset());
		
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
				a.dd(offset + (pOriginal->NTHeaders.x64.OptionalHeader.SizeOfImage - Imports[i].FirstThunk - sizeof(uint64_t) * j));
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
						LOG(Failed, MODULE_PACKER, "Failed to read string from rva %x!\n", rva);
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
								LOG(Success, MODULE_PACKER, "Emulating function at %#x\n", pRequest->dwRVA);
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
							LOG(Success, MODULE_PACKER, "Imported SDK function at %#x\n", pRequest->dwRVA);
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

		a.bind(skip);
		a.lea(rax, ptr(InternalRelOff));
		a.sub(rax, ptr(rax));
		a.mov(ptr(InternalRelOff), rax);
		a.lea(rcx, ptr(KERNEL32DLL));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(LLA));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rsi, rax);
		a.lea(rdi, ptr(import_offsets));
		if (!Options.Packing.bHideIAT) a.mov(r13, rdi);
		else a.lea(r13, ptr(import_array));
		a.lea(r12, ptr(import_names));
		a.mov(r14, 0);

		Label do_item = a.newLabel();
		Label do_lib = a.newLabel();
		Label next = a.newLabel();
		Label done = a.newLabel();
		Label skiptest = a.newLabel();
		a.bind(do_item);
		a.mov(r15, ptr(rdi));
		a.and_(r15, 0xFFFFFFFF);
		a.test(r15, r15);
		a.strict();
		a.jz(do_lib);
		a.cmp(r15, 1);
		a.strict();
		a.jz(done);
		a.test(r14, r14);
		a.strict();
		a.jz(ret);
		a.mov(rcx, r14);
		a.mov(rdx, ptr(r12));
		a.add(rdx, ptr(r12, 0x08));
		a.add(rdx, ptr(r12, 0x10));
		a.add(rdx, ptr(r12, 0x18));
		a.test(rdx, rdx);
		a.strict();
		a.jz(skiptest);
		a.mov(rdx, r12);
		if (Options.Packing.bHideIAT) {
			a.mov(r8, 1);
			a.ror(r8, 1);
			a.or_(rcx, r8);
		}
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.bind(skiptest);
		if (!Options.Packing.bHideIAT) {
			a.mov(r8, r13);
			a.sub(r8, r15);
			a.mov(qword_ptr(r8), rax);
		} else {
			Label obfuscate_ptr = a.newLabel();
			Label end_obfuscation = a.newLabel();
			a.mov(r8, 1);
			a.ror(r8, 1);
			a.and_(r8, rax);
			a.strict();
			a.jz(obfuscate_ptr);
			a.not_(r8);
			a.and_(rax, r8);
			a.jmp(end_obfuscation);

			// Encodes ptr
			a.bind(obfuscate_ptr);
			for (int i = DecoderProc.Size() - 1; i > 0; i--) {
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
					a.sub(rax, DecoderProc[i].value);
					break;
				case DI_SUB:
					a.add(rax, DecoderProc[i].value);
				}
			}
			DecoderProc.Release();
			a.mov(qword_ptr(r13), rax);
			a.mov(rax, r13);
			a.sub(rax, holder.labelOffset(import_array) - holder.labelOffset(jumper_array));
			a.sub(rax, ptr(rax));

			a.bind(end_obfuscation);
			a.lea(r8, ptr(import_offsets));
			a.sub(r8, r15);
			a.mov(qword_ptr(r8), rax);
			a.add(r13, 8);
		}
		a.add(r12, sizeof(Sha256Digest));
		a.jmp(next);

		Label next_name = a.newLabel();
		a.bind(do_lib);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.mov(rcx, r12);
		a.sub(rsp, 0x20);
		a.call(rsi);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.mov(r14, rax);
		a.bind(next_name);
		a.mov(byte_ptr(r12), 0);
		a.inc(r12);
		a.cmp(byte_ptr(r12), 0);
		a.strict();
		a.jne(next_name);
		a.inc(r12);

		a.bind(next);
		a.mov(dword_ptr(rdi), 0);
		a.add(rdi, 4);
		a.jmp(do_item);

		a.bind(ret);
		a.push(0);
		a.sub(qword_ptr(rsp), 1);
		a.popfq();
		a.jmp(entrypt);

		a.bind(done);
	}

	// Rebase image
	pOriginal->RebaseImage(pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders);

	// Handle PEs relocations
	if (!(pOriginal->NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
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
			a.mov(rcx, pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders);
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

		Buffer zero;
		zero.u64Size = pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[5].Size;
		zero.pBytes = reinterpret_cast<BYTE*>(malloc(zero.u64Size));
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress, zero.pBytes, zero.u64Size);
		zero.Release();
		pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress = pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[5].Size = 0;
	}

	// Load SDK
#define LOAD_IMPORT(name) if (ShellcodeData.RequestedFunctions.name.bRequested) { a.lea(rax, ptr(ShellcodeData.RequestedFunctions.name.Func)); a.mov(rcx, pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders + ShellcodeData.RequestedFunctions.name.dwRVA); a.add(rcx, ptr(InternalRelOff)); a.mov(qword_ptr(rcx), rax); }
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
			a.mov(rcx, pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase);
			a.add(rcx, ptr(InternalRelOff));
			a.mov(rdx, DLL_PROCESS_ATTACH);
			a.mov(r8d, 0);
			a.mov(rax, pCallbacks[i]);
			a.add(rax, ptr(InternalRelOff));
			a.call(rax);
			TLSCallbacks.Push(pCallbacks[i]);
			pCallbacks[i] = 0;
		}

		Buffer zero;
		zero.u64Size = pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[9].Size;
		zero.pBytes = reinterpret_cast<BYTE*>(malloc(zero.u64Size));
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[9].VirtualAddress, zero.pBytes, zero.u64Size);
		zero.Release();
		pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[9].VirtualAddress = pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[9].Size = 0;
	}

	// Run main entry point (if applicable)
	if (pOriginal->NTHeaders.x64.OptionalHeader.AddressOfEntryPoint) {
		a.mov(rax, pOriginal->NTHeaders.x64.OptionalHeader.AddressOfEntryPoint + ShellcodeData.OldPENewBaseRVA + pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders);
		a.add(rax, ptr(InternalRelOff));
		a.push(rax);
		a.garbage();
		if (Options.Packing.EncodingCounts > 1) {
			a.xor_(eax, eax);
			a.strict();
		}
		a.ret();
	}

	// GetLastError/SetLastError
	if (ShellcodeData.RequestedFunctions.GetLastError.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetLastError.Func);
		Mem TEB = ptr(0x30);
		TEB.setSegment(gs);
		a.mov(rax, TEB);
		a.mov(eax, ptr(rax, 0x68));
		a.ret();
	}
	if (ShellcodeData.RequestedFunctions.SetLastError.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.SetLastError.Func);
		Mem TEB = ptr(0x30);
		TEB.setSegment(gs);
		a.mov(rax, TEB);
		a.mov(ptr(rax, 0x68), ecx);
		a.mov(rax, 0);
		a.ret();
	}

	// GetSelf
	if (ShellcodeData.RequestedFunctions.GetSelf.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetSelf.Func);
		a.mov(rax, pPackedBinary->GetBaseAddress());
		a.add(rax, ptr(InternalRelOff));
		a.ret();
	}

	// GetModuleHandleW
	{
		// Labels
		Label item = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label final_check = a.newLabel();
		Label bad = a.newLabel();
		Label ret_self = a.newLabel();
		a.bind(ShellcodeData.Labels.GetModuleHandleW);

		// Asm
		a.desync();
		a.mov(rax, PEB);
		a.test(rcx, rcx);
		a.strict();
		a.jz(ret_self);
		a.mov(rax, ptr(rax, offsetof(_PEB, Ldr)));
		a.mov(rax, ptr(rax, offsetof(_PEB_LDR_DATA, InMemoryOrderModuleList)));
		a.sub(rax, 0x10);
		a.bind(item);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rax);
		a.push(rcx);
		a.lea(rcx, ptr(hash));
		a.mov(rdx, sizeof(CSha256));
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Init);
		a.pop(rcx);
		a.pop(rax);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.mov(rax, ptr(rax, 0x10));
		a.test(rax, rax);
		a.strict();
		a.jz(bad);
		a.sub(rax, 0x10);
		a.lea(r8, ptr(rax, 0x58));
		a.mov(r9, ptr(r8, 0x08));
		a.test(r9, r9);
		a.strict();
		a.jz(bad);
		a.mov(r10d, 0);
		a.bind(strcmp_loop);
		a.inc(r10);
		a.mov(r11w, word_ptr(r9, r10, 1));
		a.test(r11w, r11w);
		a.strict();
		a.jnz(strcmp_loop);
		a.shl(r10, 1);
		a.push(rax);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rcx);
		a.mov(rdx, r9);
		a.mov(r8, r10);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Update);
		a.lea(rcx, ptr(hash));
		a.lea(rdx, ptr(digest));
		a.call(Sha256_Final);
		a.mov(rax, 0);
		a.pop(rcx);
		a.lea(r11, ptr(digest));
		Label ___skip = a.newLabel();
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.high)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, high.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.low)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, high.low)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.high)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, low.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.low)));
		a.cmp(r10, ptr(rcx, offsetof(Sha256Digest, low.low)));
		a.strict();
		a.setne(al);
		a.bind(___skip);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.test(al, al);
		a.strict();
		a.pop(rax);
		a.strict();
		a.jnz(item);
		a.mov(rax, ptr(rax, 0x30));
		a.ret();
		a.bind(bad);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.ret();
		a.bind(ret_self);
		a.mov(rax, ptr(rax, 0x10));
		a.ret();
	}

	// GetProcAddressByOrdinal
	{
		a.bind(ShellcodeData.Labels.GetProcAddressByOrdinal);
		a.desync();
		a.mov(r8d, dword_ptr(rcx, 0x3C));
		a.mov(r8d, dword_ptr(rcx, r8, 0, 0x88));
		a.sub(edx, dword_ptr(rcx, r8, 0, 0x10));
		a.mov(eax, dword_ptr(rcx, r8, 0, 0x1C));
		a.add(rax, rcx);
		a.mov(eax, dword_ptr(rax, rdx, 2));
		a.add(rax, rcx);
		a.ret();
	}

	// GetStdHandle
	if (ShellcodeData.RequestedFunctions.GetStdHandle.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetStdHandle.Func);
		a.mov(rdx, PEB);
		a.mov(rdx, ptr(rdx, 0x20));
		a.mov(r8, ptr(rdx, 0x20));
		a.mov(rax, INVALID_HANDLE_VALUE);
		a.cmp(ecx, STD_INPUT_HANDLE);
		a.strict();
		a.cmovz(rax, r8);
		a.add(r8, 8);
		a.cmp(ecx, STD_OUTPUT_HANDLE);
		a.strict();
		a.cmovz(rax, r8);
		a.add(r8, 8);
		a.cmp(ecx, STD_ERROR_HANDLE);
		a.strict();
		a.cmovz(rax, r8);
		a.ret();
	}

	// Sha256
	#include "SHA256.raw"

	// GetProcAddress (emulated)
	if (ShellcodeData.RequestedFunctions.GetProcAddress.bRequested) {
		Label sum = a.newLabel();
		a.bind(sum);
		a.db(0, sizeof(Sha256Digest));

		a.bind(ShellcodeData.RequestedFunctions.GetProcAddress.Func);
		a.and_(rcx, ~(1 << 64));
		a.push(rcx);
		a.push(rdx);
		a.lea(rcx, ptr(hash));
		a.mov(rdx, sizeof(CSha256));
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Init);
		a.mov(r8, 0);
		a.dec(r8);
		a.pop(rdx);
		Label strlen_loop = a.newLabel();
		a.bind(strlen_loop);
		a.inc(r8);
		a.cmp(byte_ptr(rdx, r8), 0);
		a.strict();
		a.jnz(strlen_loop);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Update);
		a.lea(rcx, ptr(hash));
		a.lea(rdx, ptr(sum));
		a.call(Sha256_Final);
		a.pop(rcx);
		a.lea(rdx, ptr(sum));
		a.jmp(ShellcodeData.Labels.GetProcAddress);
	}

	// GetProcAddress
	{
		// Labels
		Label loop = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label found = a.newLabel();
		Label bad = a.newLabel();
		Label ret = a.newLabel();
		Label shit;
		if (Options.Packing.bHideIAT) {
			shit = a.newLabel();
			a.bind(shit);
			a.db(0);
		}
		a.bind(ShellcodeData.Labels.GetProcAddress);

		// Asm
		a.desync();
		if (Options.Packing.bHideIAT) {
			a.mov(r8, 1);
			a.ror(r8, 1);
			a.and_(r8, rcx);
			a.strict();
			a.setnz(ptr(shit));
			a.not_(r8);
			a.and_(rcx, r8);
		}
		a.push(r12);
		a.push(r13);
		a.push(r14);
		a.push(rbx);
		a.push(rsi);
		a.push(rbp);
		a.mov(r12d, 0);
		a.mov(r8d, dword_ptr(rcx, 0x3C));
		a.mov(r8d, dword_ptr(rcx, r8, 0, 0x88));
		a.mov(esi, r8d);
		a.add(rsi, rcx);
		a.mov(ebp, dword_ptr(rcx, r8, 0, 0x8C));
		a.add(rbp, rsi);
		a.mov(r9d, dword_ptr(rcx, r8, 0, 0x18));
		a.mov(r10d, dword_ptr(rcx, r8, 0, 0x20));
		a.add(r10, rcx);
		a.mov(r11d, dword_ptr(rcx, r8, 0, 0x24));
		a.add(r11, rcx);
		a.bind(loop);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rdx);
		a.push(rcx);
		a.lea(rcx, ptr(hash));
		a.mov(rdx, sizeof(CSha256));
		a.call(ShellcodeData.Labels.RtlZeroMemory);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Init);
		a.pop(rcx);
		a.pop(rdx);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.cmp(r12, r9);
		a.strict();
		a.je(bad);
		a.mov(r13d, dword_ptr(r10, r12, 2));
		a.inc(r12);
		a.add(r13, rcx);
		a.mov(r14d, 0);
		a.bind(strcmp_loop);
		a.mov(al, byte_ptr(r13, r14));
		a.test(al, al);
		a.strict();
		a.jz(found);
		a.inc(r14);
		a.jmp(strcmp_loop);
		a.bind(found);
		a.push(r8);
		a.push(r9);
		a.push(r10);
		a.push(r11);
		a.push(rdx);
		a.push(rcx);
		a.mov(rdx, r13);
		a.mov(r8, r14);
		a.lea(rcx, ptr(hash));
		a.call(Sha256_Update);
		a.lea(rcx, ptr(hash));
		a.lea(rdx, ptr(digest));
		a.call(Sha256_Final);
		Label ___skip = a.newLabel();
		a.pop(rcx);
		a.pop(rdx);
		a.lea(r11, ptr(digest));
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.high)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, high.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, high.low)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, high.low)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.high)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, low.high)));
		a.strict();
		a.setne(al);
		a.strict();
		a.jne(___skip);
		a.mov(r10, ptr(r11, offsetof(Sha256Digest, low.low)));
		a.cmp(r10, ptr(rdx, offsetof(Sha256Digest, low.low)));
		a.strict();
		a.setne(al);
		a.bind(___skip);
		a.pop(r11);
		a.pop(r10);
		a.pop(r9);
		a.pop(r8);
		a.test(al, al);
		a.strict();
		a.jnz(loop);
		Label check_in_e = a.newLabel();
		a.mov(eax, dword_ptr(rcx, r8, 0, 0x1C));
		a.add(rax, rcx);
		a.dec(r12);
		a.movzx(edx, word_ptr(r11, r12, 1));
		a.mov(eax, dword_ptr(rax, rdx, 2));
		a.add(rax, rcx);
		a.cmp(rax, rsi);
		a.strict();
		a.jge(check_in_e);
		a.jmp(ret);
		a.bind(bad);
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.bind(ret);
		if (Options.Packing.bHideIAT) {
			Label dontcheck = a.newLabel();
			Label failed = a.newLabel();

			// Verify need to check
			a.cmp(byte_ptr(shit), 0);
			a.strict();
			a.jz(dontcheck);
			a.test(rax, rax);
			a.strict();
			a.jz(dontcheck);

			// Get dll base
			a.mov(rcx, rax);
			a.mov(r8, 0xFFF);
			a.not_(r8);
			a.and_(rcx, r8);
			a.add(rcx, 0x1000);
			Label base_loop = a.newLabel();
			a.bind(base_loop);
			a.sub(rcx, 0x1000);
			a.cmp(word_ptr(rcx), IMAGE_DOS_SIGNATURE);
			a.strict();
			a.jnz(base_loop);

			// Get section header
			a.mov(edx, ptr(rcx, offsetof(IMAGE_DOS_HEADER, e_lfanew)));
			a.mov(r8, 0);
			a.mov(r8w, ptr(rcx, rdx, 0, offsetof(IMAGE_NT_HEADERS64, FileHeader) + offsetof(IMAGE_FILE_HEADER, NumberOfSections)));
			a.lea(rdx, ptr(rcx, rdx, 0, sizeof(IMAGE_NT_HEADERS64)));
			Label getheader_loop = a.newLabel();
			a.bind(getheader_loop);
			a.test(r8, r8);
			a.strict();
			a.jz(failed);
			a.mov(r9d, ptr(rdx, offsetof(IMAGE_SECTION_HEADER, VirtualAddress)));
			a.add(r9, rcx);
			a.cmp(rax, r9);
			a.strict();
			a.jl(failed);
			a.mov(ebx, ptr(rdx, offsetof(IMAGE_SECTION_HEADER, Misc.VirtualSize)));
			a.add(r9, rbx);
			a.dec(r8);
			a.add(rdx, sizeof(IMAGE_SECTION_HEADER));
			a.cmp(rax, r9);
			a.strict();
			a.jg(getheader_loop);
			a.sub(rdx, sizeof(IMAGE_SECTION_HEADER));
			a.mov(r9d, ptr(rdx, offsetof(IMAGE_SECTION_HEADER, Characteristics)));
			a.and_(r9d, IMAGE_SCN_MEM_EXECUTE);
			a.strict();
			a.jnz(dontcheck);

			a.bind(failed);
			a.mov(r8, 1);
			a.ror(r8, 1);
			a.or_(rax, r8);

			a.bind(dontcheck);
		}
		a.pop(rbp);
		a.pop(rsi);
		a.pop(rbx);
		a.pop(r14);
		a.pop(r13);
		a.pop(r12);
		a.ret();
		
		Label GPA = a.newLabel();
		a.bind(GPA);
		a.embed(&Sha256Str("GetProcAddress"), sizeof(Sha256Digest));
		Label KRN = a.newLabel();
		a.bind(KRN);
		a.embed(&Sha256WStr(L"KERNEL32.DLL"), sizeof(Sha256Digest));
		Label LLA = a.newLabel();
		a.bind(LLA);
		a.embed(&Sha256Str("LoadLibraryA"), sizeof(Sha256Digest));
		Label blank = a.newLabel();
		a.bind(blank);
		a.db(0, 64);

		a.bind(check_in_e);
		a.cmp(rax, rbp);
		a.strict();
		a.jge(ret);
		
		// Handle import thingy dothingy magigys
		DEBUG_ONLY(if (Options.Debug.bGenerateBreakpoints) a.int3());
		a.push(r12);
		a.push(r13);
		a.push(r14);
		a.push(r15);
		a.push(rax);
		a.lea(rcx, ptr(KRN));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.push(rcx);
		a.lea(rdx, ptr(GPA));
		if (Options.Packing.bHideIAT) a.mov(sil, ptr(shit));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.mov(r12, rax);
		a.pop(rcx);
		a.lea(rdx, ptr(LLA));
		a.call(ShellcodeData.Labels.GetProcAddress);
		if (Options.Packing.bHideIAT) a.mov(ptr(shit), sil);
		a.mov(r13, rax);
		a.pop(rax);
		a.lea(r14, ptr(blank));
		Label lp = a.newLabel();
		a.bind(lp);
		a.mov(cl, byte_ptr(rax));
		a.mov(byte_ptr(r14), cl);
		a.inc(r14);
		a.inc(rax);
		a.cmp(byte_ptr(rax), '.');
		a.strict();
		a.jne(lp);
		a.inc(rax);
		a.push(rax);
		a.mov(byte_ptr(r14), 0);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.lea(rcx, ptr(blank));
		a.sub(rsp, 0x20);
		a.call(r13);
		a.add(rsp, 0x20);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.pop(rdx);
		a.mov(rcx, rsp);
		a.and_(rcx, 0b1111);
		a.add(rcx, 8);
		a.sub(rsp, rcx);
		a.push(rcx);
		a.mov(rcx, rax);
		a.sub(rsp, 0x40);
		a.call(r12);
		a.add(rsp, 0x40);
		a.pop(rcx);
		a.add(rsp, rcx);
		a.pop(r15);
		a.pop(r14);
		a.pop(r13);
		a.pop(r12);
		a.jmp(ret);
	}

	// GetTickCount64
	if (ShellcodeData.RequestedFunctions.GetTickCount64.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetTickCount64.Func);
		a.mov(ecx, ptr(0x7FFE0004));
		a.shl(rcx, 0x20);
		a.mov(rax, ptr(0x7FFE0320));
		a.shl(rax, 8);
		a.mul(rcx);
		a.mov(rax, rdx);
		a.ret();
	}

	// CheckForDebuggers
	if (ShellcodeData.RequestedFunctions.CheckForDebuggers.bRequested) {
		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;
		a.align(AlignMode::kCode, alignof(CONTEXT));
		Label Context = a.newLabel();
		a.bind(Context);
		a.embed(&context, sizeof(CONTEXT));
		Label ID;
		if (Options.Packing.bDirectSyscalls) {
			ID = a.newLabel();
			a.bind(ID);
			a.dd(0);
		}
		Label NTD = a.newLabel();
		a.bind(NTD);
		a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest));
		Label GCT = a.newLabel();
		a.bind(GCT);
		a.embed(&Sha256Str("ZwGetContextThread"), sizeof(Sha256Digest));

		Label ret = a.newLabel();

		a.bind(ShellcodeData.RequestedFunctions.CheckForDebuggers.Func);
		a.push(rsi);

		// PEB check
		a.mov(rcx, PEB);
		a.mov(rax, 0);
		if (ShellcodeData.CarryData.bWasAntiDump) {
			a.or_(al, ptr(rcx, 0x10));
			a.or_(al, ptr(rcx, 0x11));
			a.or_(al, ptr(rcx, 0x12));
			a.or_(al, ptr(rcx, 0x13));
			a.or_(al, ptr(rcx, 0x14));
			a.or_(al, ptr(rcx, 0x15));
			a.or_(al, ptr(rcx, 0x16));
			a.or_(al, ptr(rcx, 0x17));
		}
		a.or_(al, byte_ptr(rcx, 0x02));
		a.mov(rdx, 0xBC);
		a.mov(r9, 0x70);
		a.mov(r8d, dword_ptr(rcx, rdx));
		a.and_(r8, r9);
		a.or_(al, r8b);
		a.or_(al, byte_ptr(0x7FFE02D4));
		a.strict();
		a.jnz(ret);

		// HWBP check
		Label hasid;
		if (Options.Packing.bDirectSyscalls) {
			hasid = a.newLabel();
			a.mov(eax, ptr(ID));
			a.test(eax, eax);
			a.strict();
			a.jnz(hasid);
		}
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(GCT));
		a.call(ShellcodeData.Labels.GetProcAddress);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		if (Options.Packing.bDirectSyscalls) {
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.mov(rcx, 1);
			a.strict();
			a.cmovnz(rax, rcx);
			a.strict();
			a.jnz(ret);
			a.mov(eax, ptr(rax, 4));
			a.mov(ptr(ID), eax);
			a.bind(hasid);
		}
		a.mov(Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.lea(rdx, ptr(Context));
		a.mov(rsi, rdx);
		if (Options.Packing.bDirectSyscalls) {
			a.syscall();
		} else {
			a.call(rax);
		}
		a.mov(rdx, rsi);
		a.test(rax, rax);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr7)));
		a.and_(rax, 0x20FF);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr6)));
		a.and_(rax, 0x0F);
		a.strict();
		a.jnz(ret);
		a.mov(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr0)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr1)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr2)));
		a.or_(rax, qword_ptr(rdx, offsetof(CONTEXT, Dr3)));
		a.bind(ret);
		a.pop(rsi);
		a.ret();
	}

	// GetCurrentThread
	if (ShellcodeData.RequestedFunctions.GetCurrentThread.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetCurrentThread.Func);
		a.mov(rax, 0xFFFFFFFFFFFFFFFE);
		a.ret();
	}

	// GetCurrentThreadId
	if (ShellcodeData.RequestedFunctions.GetCurrentThreadId.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetCurrentThreadId.Func);
		Mem TEB = qword_ptr(0x30);
		TEB.setSegment(gs);
		a.mov(rax, TEB);
		a.mov(eax, dword_ptr(rax, 0x48));
		a.ret();
	}

	// GetCurrentProcess
	if (ShellcodeData.RequestedFunctions.GetCurrentProcess.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetCurrentProcess.Func);
		a.mov(rax, 0xFFFFFFFFFFFFFFFF);
		a.ret();
	}
	
	// GetCurrentProcessId
	if (ShellcodeData.RequestedFunctions.GetCurrentProcessId.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.GetCurrentProcessId.Func);
		Mem TEB = qword_ptr(0x30);
		TEB.setSegment(gs);
		a.mov(rax, TEB);
		a.mov(eax, dword_ptr(rax, 0x40));
		a.ret();
	}

	// RtlZeroMemory
	{
		// Labels
		Label loop = a.newLabel();
		Label ret = a.newLabel();
		a.bind(ShellcodeData.Labels.RtlZeroMemory);

		a.test(rdx, rdx);
		a.strict();
		a.jz(ret);
		a.test(rcx, rcx);
		a.strict();
		a.jz(ret);
		a.mov(al, 0);
		a.bind(loop);
		a.mov(byte_ptr(rcx), al);
		a.inc(rcx);
		a.dec(rdx);
		a.strict();
		a.jnz(loop);
		a.bind(ret);
		a.ret();
	}

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
				a.dq(pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders + FunctionRanges[i].dwStart, FunctionRanges[i].Entries.Size());
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
					a.dq(pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders + FunctionRanges[i].Entries[j]);
				}
			}
			Label CompressedSizes = a.newLabel();
			a.bind(CompressedSizes);
			Label Compressed = a.newLabel();
			DWORD ID = 0;
			int count = 0;
			for (DWORD i = 0; i < FunctionRanges.Size(); i++) {
				Buffer buf;
				buf.u64Size = FunctionRanges[i].dwSize;
				buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
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

			Label UnloadSegment = a.newLabel();
			Label _UnloadSegment = a.newLabel();
			a.bind(_UnloadSegment);
			a.call(UnloadSegment);
			a.bind(LoadSegment);
			
			// Check if already loaded
			a.mov(eax, ptr(CurrentlyLoadedSegment));
			DEBUG_ONLY(Label dontkill = a.newLabel());
			DEBUG_ONLY(a.cmp(rax, ptr(rsp)));
			DEBUG_ONLY(a.strict());
			DEBUG_ONLY(a.jne(dontkill));
			DEBUG_ONLY(a.int3());
			DEBUG_ONLY(a.bind(dontkill));
			a.cmp(eax, count);
			a.strict();
			a.jl(_UnloadSegment);
			
			// Load segment
			a.pop(rax);
			a.mov(ptr(CurrentlyLoadedSegment), eax);
			a.push(rcx);
			a.push(rdx);
			a.push(r8);
			a.push(r9);
			a.push(r10);
			a.push(r11);
			a.mov(rdx, 0);
			a.lea(rcx, ptr(Compressed));
			a.lea(r8, ptr(CompressedSizes));
			a.lea(r11, ptr(PointerArray));
			a.mov(r9, ptr(r11, rax, 3));
			Label findcomploop = a.newLabel();
			Label findcomploopexit = a.newLabel();
			a.bind(findcomploop);
			a.cmp(edx, eax);
			a.strict();
			a.jge(findcomploopexit);
			a.mov(r10, ptr(r11, rdx, 3));
			a.add(rcx, ptr(r8));
			Label thing = a.newLabel();
			a.bind(thing);
			a.add(r8, 8);
			a.inc(rdx);
			a.cmp(r10, ptr(r11, rdx, 3));
			a.strict();
			a.jz(thing);
			a.cmp(r9, ptr(r11, rdx, 3));
			a.strict();
			a.jnz(findcomploop);
			a.bind(findcomploopexit);
			a.mov(rdx, ptr(r8));
			a.lea(r8, ptr(PointerArray));
			a.mov(r8, ptr(r8, rax, 3));
			a.add(r8, ptr(InternalRelOff));
			a.lea(r9, ptr(SizeArray));
			a.mov(r9d, ptr(r9, rax, 2));
			a.sub(rsp, 0x40);
			a.call(Unpack);
			a.add(rsp, 0x40);
			a.pop(r11);
			a.pop(r10);
			a.pop(r9);
			a.pop(r8);
			a.pop(rdx);
			a.mov(ecx, ptr(CurrentlyLoadedSegment));
			a.lea(rax, ptr(EntryArray));
			a.mov(rax, ptr(rax, ecx, 3));
			a.add(rax, ptr(InternalRelOff));
			a.pop(rcx);
			a.xchg(ptr(rsp), rax);
			a.add(rsp, 8);

			// Call function
			Label nflagisset = a.newLabel();
			a.block();
			a.cmp(byte_ptr(Flag), 0);
			a.block();
			a.je(nflagisset);
			a.mov(byte_ptr(Flag), 0);
			a.ret();
			a.bind(nflagisset);
			a.block();
			a.call(ptr(rsp, -8));
			
			// Check if return address is in another segment
			a.xchg(ptr(rsp), rax);
			a.push(rcx);
			a.push(rdx);
			a.push(r8);
			a.push(r9);
			a.push(r10);
			a.push(r11);
			a.mov(rcx, 0);
			a.dec(rcx);
			a.mov(r11, 1);
			a.lea(r8, ptr(PointerArray));
			a.lea(r9, ptr(SizeArray));
			Label checkexit = a.newLabel();
			Label checkloop = a.newLabel();
			a.bind(checkloop);
			a.cmp(rcx, count);
			a.strict();
			a.jge(checkexit);
			a.inc(rcx);
			a.mov(rdx, ptr(r8, rcx, 3));
			a.add(rdx, ptr(InternalRelOff));
			a.cmp(rax, rdx);
			a.strict();
			a.jl(checkloop);
			a.mov(r10d, ptr(r9, rcx, 2));
			a.add(rdx, r10);
			a.cmp(rax, rdx);
			a.strict();
			a.setl(byte_ptr(Flag));
			a.strict();
			a.jl(checkexit);
			a.jmp(checkloop);
			a.bind(checkexit);
			a.pop(r11);
			a.pop(r10);
			a.pop(r9);
			a.pop(r8);
			a.pop(rdx);
			Label dothingy = a.newLabel();
			a.cmp(byte_ptr(Flag), 0);
			a.strict();
			a.jne(dothingy);
			a.pop(rcx);
			a.xchg(ptr(rsp), rax);
			a.jmp(UnloadSegment);
			a.bind(dothingy);
			a.xchg(ptr(rsp, 8), rax);
			a.push(rcx);
			a.xchg(ptr(rsp, 8), rax);
			a.mov(rcx, rax);
			a.jmp(LoadSegment);

			// Write function address
			for (DWORD i = 0; i < FunctionRanges.Size(); i++) {
				for (int j = 0; j < FunctionRanges[i].Entries.Size(); j++) {
					pOriginal->WriteRVA<uint64_t>(FunctionRanges[i].Entries[j] + 8, pPackedBinary->GetBaseAddress() + holder.labelOffsetFromBase(LoadSegment) + ShellcodeData.BaseAddress);
					ShellcodeData.Relocations.Relocations.Push(ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders + FunctionRanges[i].Entries[j] + 8);
				}
			}

			a.bind(UnloadSegment);
			a.push(rax);
			a.push(rcx);
			a.push(rdx);
			a.push(r8);
			a.push(r9);
			a.mov(eax, ptr(CurrentlyLoadedSegment));
			a.lea(rcx, ptr(PointerArray));
			a.mov(rcx, ptr(rcx, rax, 3));
			a.add(rcx, ptr(InternalRelOff));
			a.lea(rdx, ptr(SizeArray));
			a.mov(edx, ptr(rdx, rax, 2));
			a.push(rax);
			Label loop = a.newLabel();
			a.mov(al, 0xCC);
			a.bind(loop);
			a.mov(byte_ptr(rcx), al);
			a.inc(rcx);
			a.dec(rdx);
			a.strict();
			a.jnz(loop);
			a.pop(r8);
			a.mov(r9, r8);
			a.lea(rcx, ptr(PointerArray));
			Label decloop = a.newLabel();
			a.bind(decloop);
			a.dec(r9);
			a.mov(rdx, ptr(rcx, r8, 3));
			a.cmp(rdx, ptr(rcx, r9, 3));
			a.strict();
			a.jz(decloop);
			a.inc(r9);
			a.mov(r8, r9);
			Label setentryloop = a.newLabel();
			a.bind(setentryloop);
			a.lea(rcx, ptr(EntryArray));
			a.mov(rcx, ptr(rcx, r8, 3));
			a.add(rcx, ptr(InternalRelOff));
			a.mov(word_ptr(rcx), 0x6850);
			a.mov(dword_ptr(rcx, 2), r8d);
			a.mov(word_ptr(rcx, 6), 0xB848);
			a.lea(rax, ptr(LoadSegment));
			a.mov(qword_ptr(rcx, 8), rax);
			a.mov(qword_ptr(rcx, 16), 0xE0FF);
			a.inc(r8);
			a.lea(rcx, ptr(PointerArray));
			a.mov(rdx, ptr(rcx, r8, 3));
			a.cmp(rdx, ptr(rcx, r9, 3));
			a.strict();
			a.jz(setentryloop);
			a.mov(dword_ptr(CurrentlyLoadedSegment), _I32_MAX);
			a.pop(r9);
			a.pop(r8);
			a.pop(rdx);
			a.pop(rcx);
			a.pop(rax);
			a.ret();

			a.bind(Compressed);
			for (int i = 0; i < FunctionBodies.Size(); i++) {
				a.embed(FunctionBodies[i].pBytes, FunctionBodies[i].u64Size);
				free(FunctionBodies[i].pBytes);
			}
			FunctionBodies.Release();

			GenerateUnpackingAlgorithm(&a, Unpack);
		}
	}

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress);
	if (bAsmJitFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to generate internal shellcode\n");
		return buf;
	}
	LOG(Info_Extended, MODULE_PACKER, "Internal code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	ShellcodeData.LoadedOffset = holder.labelOffsetFromBase(entrypt) + holder.baseAddress();
	if (holder.hasRelocEntries()) {
		for (int i = 0; i < holder.relocEntries().size(); i++) {
			if (holder.relocEntries()[i]->_relocType == RelocType::kNone) continue;
			ShellcodeData.Relocations.Relocations.Push(holder.baseAddress() + holder.relocEntries()[i]->sourceOffset() - pPackedBinary->NTHeaders.x64.OptionalHeader.ImageBase);
		}
	}

	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
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
	if (!(pOriginal->NTHeaders.x64.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) || (pOriginal->NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		LOG(Failed, MODULE_PACKER, "Binary must be relocatable to be packed\n");
		return false;
	}

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
	pPackedBinary->DosStub.u64Size = pOriginal->DosStub.u64Size;
	pPackedBinary->DosStub.pBytes = reinterpret_cast<BYTE*>(malloc(pPackedBinary->DosStub.u64Size));
	memcpy(pPackedBinary->DosStub.pBytes, pOriginal->DosStub.pBytes, pOriginal->DosStub.u64Size);
	pPackedBinary->DosHeader.e_magic = IMAGE_DOS_SIGNATURE;
	pPackedBinary->DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + pPackedBinary->DosStub.u64Size;

	// Save resources
	Buffer resources = { 0 };
	if (Options.Packing.bDontCompressRsrc && pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[2].Size && pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[2].VirtualAddress) {
		IMAGE_DATA_DIRECTORY rsrc = pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[2];
		IMAGE_SECTION_HEADER Header = pOriginal->SectionHeaders[pOriginal->FindSectionByRVA(rsrc.VirtualAddress)];
		Buffer raw = pOriginal->SectionData[pOriginal->FindSectionByRVA(rsrc.VirtualAddress)];
		if (!raw.pBytes || !raw.u64Size || !Header.PointerToRawData) {
			LOG(Warning, MODULE_PACKER, "A resource section was present, but resources could not be read! (RVA: %x)\n", rsrc.VirtualAddress);
		} else {
			resources.pBytes = reinterpret_cast<BYTE*>(malloc(resources.u64Size = rsrc.Size));
			memcpy(resources.pBytes, raw.pBytes + rsrc.VirtualAddress - Header.VirtualAddress, resources.u64Size);
			ZeroMemory(raw.pBytes + rsrc.VirtualAddress - Header.VirtualAddress, resources.u64Size);
		}
	}

	// NT headers
	bool bIsDLL = pOriginal->NTHeaders.x64.FileHeader.Characteristics & IMAGE_FILE_DLL;
	IMAGE_NT_HEADERS64* pNT = &pPackedBinary->NTHeaders.x64;
	pNT->Signature = IMAGE_NT_SIGNATURE;
	pNT->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	pNT->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
	pNT->FileHeader.Characteristics = (bIsDLL ? IMAGE_FILE_DLL : 0) | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	DEBUG_ONLY(if (Options.Debug.bDisableRelocations) pNT->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED);
	pNT->OptionalHeader.Magic = 0x20B;
	pNT->OptionalHeader.SectionAlignment = 0x1000;
	pNT->OptionalHeader.FileAlignment = 0x200;
	ShellcodeData.ImageBase = pNT->OptionalHeader.ImageBase = pOriginal->GetBaseAddress();
	pNT->OptionalHeader.MajorOperatingSystemVersion = 4;
	pNT->OptionalHeader.MajorSubsystemVersion = 6;
	pNT->OptionalHeader.SizeOfHeaders = pPackedBinary->DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * 2;
	pNT->OptionalHeader.Subsystem = pOriginal->NTHeaders.x64.OptionalHeader.Subsystem;
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
	ShellcodeData.BaseAddress = ShellcodeData.OldPENewBaseRVA + pOriginal->NTHeaders.x64.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders;
	ShellcodeData.bUsingTLSCallbacks = Options.Packing.bDelayedEntry || Options.Packing.bAntiDebug || Options.Packing.bAntiPatch || (pOriginal->GetTLSCallbacks() && *pOriginal->GetTLSCallbacks());
	ShellcodeData.EntryOff = 0x30 + rand() & 0xCF;
	Buffer Internal = GenerateInternalShellcode(pOriginal, pPackedBinary);
	if (!Internal.u64Size || !Internal.pBytes) return false;
	SecHeader.Misc.VirtualSize = Internal.u64Size + pOriginal->NTHeaders.x64.OptionalHeader.SizeOfImage - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders;
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
		TLSDataDir.AddressOfCallBacks = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_TLS_DIRECTORY64) + pPackedBinary->GetBaseAddress();
		TLSDataDir.AddressOfIndex = TLSDataDir.StartAddressOfRawData = TLSDataDir.AddressOfCallBacks + sizeof(uint64_t) * nTLSEntries;
		TLSDataDir.EndAddressOfRawData = TLSDataDir.StartAddressOfRawData + sizeof(uint64_t) * nTLSEntries;
		shell.u64Size += sizeof(uint64_t) * (nTLSEntries + 1) + sizeof(IMAGE_TLS_DIRECTORY64) + TLSCode.u64Size;
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		memcpy(shell.pBytes + shell.u64Size - (sizeof(uint64_t) * (nFalseEntries + 2) + sizeof(IMAGE_TLS_DIRECTORY64) + TLSCode.u64Size), &TLSDataDir, sizeof(IMAGE_TLS_DIRECTORY64));
		memcpy(shell.pBytes + shell.u64Size - TLSCode.u64Size, TLSCode.pBytes, TLSCode.u64Size);
		uint64_t* pEntries = reinterpret_cast<uint64_t*>(shell.pBytes + shell.u64Size - (sizeof(uint64_t) * (nTLSEntries + 1) + TLSCode.u64Size));
		pEntries[1 + nFalseEntries] = 0;
		pEntries[0] = SecHeader.VirtualAddress + shell.u64Size - TLSCode.u64Size + pPackedBinary->GetBaseAddress();
		for (int i = 1; i < nTLSEntries; i++) {
			pEntries[i] = pPackedBinary->GetBaseAddress() + SecHeader.VirtualAddress + shell.u64Size + resources.u64Size + pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[0].Size + 0x10000 + rand();
		}

		TLSCode.Release();
	}

	// Relocations
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
				Relocations.Push(TLSDataDir.AddressOfCallBacks - pPackedBinary->GetBaseAddress() + sizeof(uint64_t) * i);
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
		pPackedBinary->NTHeaders.x64.OptionalHeader.DataDirectory[2].Size = resources.u64Size;
		pPackedBinary->NTHeaders.x64.OptionalHeader.DataDirectory[2].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;

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
					pResource->OffsetToData += pPackedBinary->NTHeaders.x64.OptionalHeader.DataDirectory[2].VirtualAddress - pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[2].VirtualAddress;
				}
			}
		} while (Offsets.Size());

		shell.Merge(resources);
	}

	// Exports
	if (pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress && pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[0].Size) {
		IMAGE_EXPORT_DIRECTORY Exports = { 0 };
		IMAGE_EXPORT_DIRECTORY OriginalExports = pOriginal->ReadRVA<IMAGE_EXPORT_DIRECTORY>(pOriginal->NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress);
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
		shell.u64Size += sizeof(IMAGE_EXPORT_DIRECTORY);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		memcpy(shell.pBytes + shell.u64Size - sizeof(IMAGE_EXPORT_DIRECTORY), &Exports, sizeof(IMAGE_EXPORT_DIRECTORY));

		// Export RVAs
		shell.u64Size += exports.Size() * sizeof(DWORD);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		for (int i = 0; i < exports.Size(); i++) {
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (exports.Size() - i)) = exports[i] + ShellcodeData.OldPENewBaseRVA - pOriginal->NTHeaders.x64.OptionalHeader.SizeOfHeaders;
		}

		// Export names
		shell.u64Size += names.Size() * sizeof(DWORD);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		DWORD rva = Exports.AddressOfNameOrdinals + sizeof(WORD) * names.Size();
		for (int i = 0; i < names.Size(); i++) {
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (names.Size() - i)) = rva;
			rva += lstrlenA(names[i]) + 1;
		}

		// Export ordinals
		shell.u64Size += names.Size() * sizeof(WORD);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		for (WORD i = 0; i < names.Size(); i++) {
			*reinterpret_cast<WORD*>(shell.pBytes + shell.u64Size - sizeof(WORD) * (names.Size() - i)) = i;
		}

		// Export names
		for (int i = 0; i < names.Size(); i++) {
			int len = lstrlenA(names[i]) + 1;
			shell.u64Size += len;
			shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
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
	if (Options.Packing.bDelayedEntry) pPackedBinary->NTHeaders.x64.OptionalHeader.AddressOfEntryPoint = pPackedBinary->SectionHeaders[0].VirtualAddress;

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
		Sha256_Update(&hash, (Byte*)&pPackedBinary->NTHeaders.x64, sizeof(IMAGE_NT_HEADERS64));
		Sha256_Final(&hash, (Byte*)&Digest);
		pPackedBinary->WriteRVA<Sha256Digest>(pPackedBinary->GetTLSCallbacks()[0] - pPackedBinary->GetBaseAddress() + ShellcodeData.AntiPatchData.dwOffHeaderSum, Digest);
	}

	// Finalize
	if (Options.Packing.EncodingCounts > 1) {
		delete pOriginal;
	}
	pPackedBinary->Status = Normal;
	return true;
}