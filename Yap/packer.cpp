#include "packer.hpp"
#include "lzma/Aes.h"
#include "lzma/Sha256.h"

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

Vector<uint64_t> TLSCallbacks;

// Handle AsmJit errors
class AsmJitErrorHandler : public ErrorHandler {
public:
	void handleError(_In_ Error error, _In_ const char* message, _In_ BaseEmitter* emitter) override {
		LOG(Failed, MODULE_PACKER, "AsmJit error: %s\n", message);
	}
};

uint64_t rand64() {
	uint64_t ret = rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	ret = ret << 16 | rand();
	return ret;
}

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

Buffer PackSection(_In_ Buffer SectionData, _In_ PackerOptions Options) {
	Buffer data = { 0 };
	data.u64Size = SectionData.u64Size;
	data.pBytes = reinterpret_cast<BYTE*>(malloc(data.u64Size));

	// props
	CLzmaEncProps props = { 0 };
	props.level = ::Options.Packing.CompressionLevel;
	props.numThreads = 1;
	props.dictSize = 1 << 24;
	props.lc = 3;
	props.pb = 2;
	props.algo = 1;
	props.fb = 5 + 27 * ::Options.Packing.CompressionLevel;
	props.btMode = 1;
	props.numHashBytes = 4;
	props.mc = 1 + 0x1C71C71C71C7 * ::Options.Packing.CompressionLevel;
		
	ICompressProgress progress = { 0 };
	progress.Progress = PackingProgress;
	ISzAlloc alloc = { 0 };
	alloc.Alloc = Alloc;
	alloc.Free = Free;
	size_t propssz = LZMA_PROPS_SIZE;
	LzmaEncode(data.pBytes, &data.u64Size, SectionData.pBytes, SectionData.u64Size, &props, ShellcodeData.UnpackData.EncodedProp, &propssz, 0, &progress, &alloc, &alloc);
	data.pBytes = reinterpret_cast<BYTE*>(realloc(data.pBytes, data.u64Size));
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

	// Data
	Label _skipdata = pA->newLabel();
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

	pA->bind(_skipdata);
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
	pA->call(ShellcodeData.Labels.GetProcAddressA);
	pA->mov(ptr(ptr_HeapFree), rax);
	pA->lea(rdx, ptr(HA));
	pA->call(ShellcodeData.Labels.GetProcAddressA);
	pA->mov(ptr(ptr_HeapAlloc), rax);
	pA->pop(r9);
	pA->pop(rcx);
	pA->pop(r8);
	pA->pop(rdx);
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
	pA->pop(r9);
	pA->pop(r8);
	pA->ret();
	
	// LzmaDecode
	#include "LzmaDecode.raw"

	// LzmaDec_DecodeToDic
	#include "LzmaDec_DecodeToDic.raw"

	// LzmaDec_TryDummy
	#include "LzmaDec_TryDummy.raw"

	// LzmaDec_DecodeReal
	#include "LzmaDec_DecodeReal.raw"
}

Buffer GenerateTLSShellcode(_In_ PackerOptions Options, _In_ PE* pPackedBinary, _In_ PE* pOriginal) {
	// Setup
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);

	// Check if its process start TLS
	Label hidethread;
	if (::Options.Packing.bAntiDebug) hidethread = a.newLabel();
	Label _do = a.newLabel();
	a.desync();
	a.desync_mov(rax);
	Label reloc = a.newLabel();
	a.cmp(rdx, 1);
	a.strict();
	a.je(_do);

	// If it's not, call packed binaries TLS callbacks (if unpacked)
	if (TLSCallbacks.Size()) {
		if (::Options.Packing.bAntiDebug) {
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
			a.mov(rax, TLSCallbacks.At(i));
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
	if (::Options.Packing.bAntiDebug) a.call(hidethread);
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
	if (::Options.Packing.bAntiDebug) {
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
		a.mov(rcx, rax);
		for (int i = 0; i < 32; i++) {
			a.shl(rcx, 1);
			a.or_(rcx, rax);
		}
		a.push(rcx);
		a.mov(rcx, 0);
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3(); a.block());
		a.popfq();
		a.block();
		a.jz(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress - (rand() & 0xFFFF));
	}
	if (::Options.Packing.bDelayedEntry) {
		a.mov(rax, pPackedBinary->GetBaseAddress() + pPackedBinary->GetSectionHeaders()[0].VirtualAddress);
		a.add(rax, ptr(reloc));
		if (::Options.Packing.bAntiDebug) {
			a.cmp(byte_ptr(rax), 0xCC);
			a.mov(rcx, 0);
			a.cmovnz(rcx, rax);
			a.cmp(word_ptr(rax), 0x03CD);
			a.mov(byte_ptr(rax), 0xC3);
			a.mov(rax, rcx);
			a.cmovz(rax, rsp);
			a.call(rax);
			a.mov(byte_ptr(rax), 0x00);
		}
		a.add(rax, 2 * (rand64() % (pPackedBinary->GetSectionHeaders()[0].Misc.VirtualSize / 2)));
		a.mov(word_ptr(rax), 0xB848);
		a.add(rax, 2);
		a.mov(rcx, pPackedBinary->GetBaseAddress() + pPackedBinary->GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint + ShellcodeData.EntryOff);
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

	if (::Options.Packing.bAntiDebug) {
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
		a.call(pPackedBinary->GetBaseAddress() + ShellcodeData.GetProcAddressAOff);
		a.mov(::Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.mov(rdx, 17);
		a.mov(r8, 0);
		if (::Options.Packing.bDirectSyscalls) {
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
		a.ret();
	}

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress);
	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	LOG(Success, MODULE_PACKER, "Generated TLS shellcode\n");
	return buf;
}

Buffer GenerateLoaderShellcode(_In_ PE* pOriginal, _In_ PackerOptions Options, _In_ PE* pPackedBinary, _In_ Buffer InternalShellcode) {
	// Setup asmjit
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	ShellcodeData.Labels.GetModuleHandleW = a.newLabel();
	ShellcodeData.Labels.GetProcAddressA = a.newLabel();
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
	if (!::Options.Packing.bDelayedEntry) {
		switch (::Options.Packing.Immitate) {
		case ExeStealth:
			a.db(0xEB);
			a.db(sizeof("ExeStealth V2 Shareware "));
			a.embed("ExeStealth V2 Shareware ", sizeof("ExeStealth V2 Shareware "));
			break;
		}
	} else {
		for (int i = 0; i < ShellcodeData.EntryOff; i++) a.db(rand() & 255);
	}

	// Entry point
	if (DEBUG_ONLY(!::Options.Debug.bDisableMutations) RELEASE_ONLY(true)) {
		a.strict();
		a.jz(_entry);
		a.garbage();
	} else {
		a.jmp(_entry);
	}

	// Data
	if (Options.Message) {
		a.bind(message);
		a.embed(Options.Message, lstrlenA(Options.Message) + 1);
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
	if (Options.Message) {
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
	if (::Options.Packing.bOnlyLoadMicrosoft) {
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
	if (::Options.Packing.bOnlyLoadMicrosoft) {
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(SIP));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		Label skippolicy = a.newLabel();
#ifdef _DEBUG
		if (::Options.Debug.bDisableMutations) {
		a.jmp(skippolicy);
		} else {
			a.strict();
			a.jnz(skippolicy);
		}
#else
		a.strict();
		a.jnz(skippolicy);
#endif
		
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
		a.mov(::Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFF);
		a.mov(edx, 52);
		a.lea(r8, ptr(policy));
		a.mov(r9d, holder.labelOffset(skippolicy) - holder.labelOffset(policy));
		if (::Options.Packing.bDirectSyscalls) {
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
	if (::Options.Packing.bAntiDebug) {
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(::Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.lea(rdx, ptr(Context));
		a.mov(rsi, rdx);
		if (::Options.Packing.bDirectSyscalls) {
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
	if (::Options.Packing.bAntiVM) {
		a.mov(eax, 1);
		a.cpuid();
		a.bt(ecx, 31);
		a.strict();
		if (!::Options.Packing.bAllowHyperV) {
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
	if (::Options.Packing.bAntiSandbox) {
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r13, rax);
		a.pop(rcx);
		a.lea(rdx, ptr(LLA));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.lea(rcx, ptr(USR));
		a.push(rsi);
		a.push(rbx);
		a.call(rax); // I actually just don't understand why LoadLibraryA crashes here and it's confusing me
		a.add(rsp, 0x10);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(GCP));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r12, rax);
		a.lea(rcx, ptr(PT));
		a.call(r12);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(r14, ptr(PT));
		a.bind(_loop);
		a.mov(ecx, 5);
		a.call(r13);
		a.lea(rcx, ptr(PT));
		a.call(r12);
		a.test(rax, rax);
		a.strict();
		a.jz(_loop);
		a.cmp(r14, ptr(PT));
		a.strict();
		a.jz(_loop);
	}

	if (::Options.Packing.bAntiDump) {
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
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
		a.mov(r8, 0x40);
		a.lea(r9, ptr(KRN));
		a.mov(rsi, rax);
		a.sub(rsp, 0x18);
		a.call(rax);
		a.add(rsp, 0x18);
		a.pop(rcx);
		a.pop(rdx);
		a.call(ShellcodeData.Labels.RtlZeroMemory);
	}

	// Load each section
	Label* pLabels = reinterpret_cast<Label*>(malloc(sizeof(Label) * pOriginal->GetNtHeaders()->x64.FileHeader.NumberOfSections));
	PE Copied(pOriginal);

	BYTE* workspace = reinterpret_cast<BYTE*>(malloc(0xFFFFFF));
	for (WORD i = 0, n = pOriginal->GetNtHeaders()->x64.FileHeader.NumberOfSections; i < n; i++) {
		if (!pOriginal->GetSectionHeader(i)->Misc.VirtualSize || !pOriginal->GetSectionHeader(i)->SizeOfRawData) continue;
		
		// Compress data
		Buffer compressed = PackSection(pOriginal->GetSectionBytes(i), Options);
		LOG(Info, MODULE_PACKER, "Packed section %.8s (%lld)\n", pOriginal->GetSectionHeader(i)->Name, (int64_t)compressed.u64Size - pOriginal->GetSectionHeader(i)->SizeOfRawData);
		Copied.OverwriteSection(i, compressed.pBytes, compressed.u64Size);
		
		// Decompress data
		
		pLabels[i] = a.newLabel();
		a.lea(rcx, ptr(pLabels[i]));
		a.mov(rdx, compressed.u64Size);
		a.mov(r8, pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA + pOriginal->GetSectionHeader(i)->VirtualAddress - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);
		a.add(r8, ptr(Reloc));
		a.mov(r9, pOriginal->GetSectionBytes(i).u64Size);
		a.call(unpack);
	}
	Label InternalShell = a.newLabel();
	ULONG sz = 0;
	Buffer CompressedInternal = PackSection(InternalShellcode, Options);
	a.lea(rcx, ptr(InternalShell));
	a.mov(rdx, CompressedInternal.u64Size);
	a.mov(r8, pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA + pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfImage - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);
	a.add(r8, ptr(Reloc));
	a.mov(r9, InternalShellcode.u64Size);
	a.call(unpack);
	free(workspace);

	// Relocation stuff
	a.mov(rax, ptr(Reloc));
	if (ShellcodeData.Relocations.Relocations.Size()) {
		for (int i = 0, n = ShellcodeData.Relocations.Relocations.Size(); i < n; i++) {
			a.mov(r10, pPackedBinary->GetBaseAddress() + ShellcodeData.Relocations.Relocations.At(i));
			a.add(r10, rax);
			a.add(ptr(r10), rax);
		}
		ShellcodeData.Relocations.Relocations.Release();
	}
	a.mov(rcx, rax);

	a.desync();
	a.mov(rax, pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA + pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfImage - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);
	a.add(rax, rcx);
	Label szshell = a.newLabel();
	if (::Options.Packing.bAntiDump) {
		a.lea(rcx, ptr(rip));
		a.sub(rcx, a.offset());
		a.mov(rdx, ptr(szshell));
	}
	DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3(); a.block());
	a.call(rax);
	a.garbage();

	// Insert compressed data
	for (WORD i = 0, n = pOriginal->GetNtHeaders()->x64.FileHeader.NumberOfSections; i < n; i++) {
		if (!pOriginal->GetSectionHeader(i)->Misc.VirtualSize || !pOriginal->GetSectionHeader(i)->SizeOfRawData) continue;
		a.bind(pLabels[i]);
		Buffer buf = Copied.GetSectionBytes(i);
		for (int j = 0; j < buf.u64Size; j++) a.db(buf.pBytes[j]);
	}
	size_t szOffSzShell = 0;
	if (::Options.Packing.bAntiDump) {
		a.bind(szshell);
		szOffSzShell = a.offset();
		a.dq(0);
	}
	a.bind(InternalShell);
	for (int i = 0; i < CompressedInternal.u64Size; i++) a.db(CompressedInternal.pBytes[i]);

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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.ret();
		a.bind(ret_self);
		a.mov(rax, ptr(rax, 0x10));
		a.ret();
	}

	// Sha256
	#include "SHA256.raw"

	GenerateUnpackingAlgorithm(&a, unpack);

	// GetProcAddressA
	{
		// Labels
		Label loop = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label found = a.newLabel();
		Label bad = a.newLabel();
		Label ret = a.newLabel();
		a.bind(ShellcodeData.Labels.GetProcAddressA);

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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
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
	ShellcodeData.GetModuleHandleWOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetModuleHandleW);
	ShellcodeData.GetProcAddressAOff = ShellcodeData.BaseAddress + holder.labelOffsetFromBase(ShellcodeData.Labels.GetProcAddressA);
	LOG(Info, MODULE_PACKER, "Loader code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	ShellcodeData.TrueEntryOffset = holder.labelOffsetFromBase(_entry);
	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	if (::Options.Packing.bAntiDump) *reinterpret_cast<QWORD*>(buf.pBytes + szOffSzShell) = buf.u64Size;
	free(pLabels);
	free(CompressedInternal.pBytes);
	LOG(Success, MODULE_PACKER, "Generated loader shellcode\n");
	return buf;
}

Buffer GenerateInternalShellcode(_In_ PE* pOriginal, _In_ PackerOptions Options, _In_ PE* pPackedBinary) {
	// Setup asmjit
	Buffer buf = { 0 };
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	a.desync();
	Label KERNEL32DLL = a.newLabel();
	Label NTD = a.newLabel();
	Label SIP = a.newLabel();
	Label Sha256_Init = a.newLabel();
	Label Sha256_Update = a.newLabel();
	Label Sha256_Final = a.newLabel();
	ShellcodeData.Labels.GetModuleHandleW = a.newLabel();
	ShellcodeData.Labels.GetProcAddressByOrdinal = a.newLabel();
	ShellcodeData.Labels.GetProcAddressA = a.newLabel();
	ShellcodeData.Labels.RtlZeroMemory = a.newLabel();

	// PEB memory thingy (gs:[0x60])
	Mem PEB = ptr(0x60);
	PEB.setSegment(gs);

	Label entrypt = a.newLabel();
	a.bind(entrypt);
	if (::Options.Packing.bAntiDump) {
		a.call(ShellcodeData.Labels.RtlZeroMemory);
	}
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
	if (::Options.Packing.bMarkCritical) {
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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
		a.ret();

		a.bind(_skip);
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(SIP));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(::Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFF);
		a.mov(edx, 0x1D);
		a.lea(r8, ptr(data));
		a.mov(r9d, 4);
		if (::Options.Packing.bDirectSyscalls) {
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.jnz(ret);
			a.mov(eax, ptr(rax, 4));
			a.syscall();
		} else {
			a.call(rax);
		}
	}

	// Masquerading
	if (Options.sMasqueradeAs) {
		Label not_found = a.newLabel();
		Label new_buf = a.newLabel();
		Label copy_byte = a.newLabel();
		Label zero_remainder = a.newLabel();
		BYTE XORKey = rand() & 255;

		// Check buffer size
		a.mov(rax, PEB);
		a.mov(rax, ptr(rax, 0x20));
		a.mov(si, word_ptr(rax, 0x62));
		a.cmp(si, 2 * (lstrlenA(Options.sMasqueradeAs) + 1));
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
		a.mov(bx, 2 * lstrlenA(Options.sMasqueradeAs)); // Get data
		a.mov(cx, 2 * (lstrlenA(Options.sMasqueradeAs) + 1));
		a.mov(rdx, ptr(rax, 0x68));
		a.mov(word_ptr(rax, 0x70), bx); // CommandLine
		a.mov(word_ptr(rax, 0x72), cx);
		a.mov(ptr(rax, 0x78), rdx);
		a.mov(word_ptr(rax, 0xB0), bx); // WindowTitle
		a.mov(word_ptr(rax, 0xB2), cx);
		a.mov(ptr(rax, 0xB8), rdx);
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
		for (int i = 0, n = lstrlenA(Options.sMasqueradeAs) + 1; i < n; i++) a.db(Options.sMasqueradeAs[i] ^ XORKey);

		a.bind(not_found);
	}

	// Sideloading protection
	if (::Options.Packing.bMitigateSideloading) {
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.lea(rcx, ptr(ZRO));
		a.call(rax);
		a.mov(rcx, rsi);
		a.lea(rdx, ptr(SSP));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(ecx, BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);
		a.call(rax);
		
		a.bind(ret);
	}

	a.garbage();

	// Handle original PE's imports
	VirtualizeResult VirtRes;
	Label InternalRelOff;
	Vector<IMAGE_IMPORT_DESCRIPTOR> Imports = pOriginal->GetImportedDLLs();
	if (!Imports.nItems || !Imports.raw.pBytes || !Imports.raw.u64Size) {
		if (::Options.Packing.EncodingCounts <= 1) LOG(Warning, MODULE_PACKER, "No imports were found, assuming there are no imported DLLs.\n");
		Label skip = a.newLabel();
		a.jmp(skip);
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

		// jmp qword ptr [rip] for every import
		Label import_jumpers;
		Vector<size_t> Offsets;
		if (::Options.Packing.bHideIAT) {
			import_jumpers = a.newLabel();
			a.bind(import_jumpers);
			for (int j, i = 0; i < Imports.Size(); i++) {
				char* name = pOriginal->ReadRVAString(Imports.At(i).Name);
				if (!lstrcmpA(name, "yap.dll")) {
					LOG(Info_Extended, MODULE_PACKER, "SDK imported\n");
					ShellcodeData.RequestedFunctions.iIndex = i;
					continue;
				}
				j = 0;
				while (pOriginal->ReadRVA<uint64_t>(Imports.At(i).OriginalFirstThunk + sizeof(uint64_t) * j)) {
					a.block();
					a.jmp(qword_ptr(rip));
					Offsets.Push(a.offset());
					a.dq(rand64());
					j++;
				}
			}
		}

		InternalRelOff = a.newLabel();
		a.bind(InternalRelOff);
		a.dq(ShellcodeData.BaseAddress + pPackedBinary->GetBaseAddress() + a.offset());
		
		// Offsets
		Label import_offsets = a.newLabel();
		int64_t offset = a.offset();
		a.bind(import_offsets);
		for (int j, i = 0; i < Imports.Size(); i++) {
			char* name = pOriginal->ReadRVAString(Imports.At(i).Name);
			if (!::Options.Packing.bHideIAT && !lstrcmpA(name, "yap.dll")) {
				LOG(Info_Extended, MODULE_PACKER, "SDK imported\n");
				ShellcodeData.RequestedFunctions.iIndex = i;
				continue;
			}
			j = 0;
			a.dd(0);
			while (pOriginal->ReadRVA<uint64_t>(Imports.At(i).OriginalFirstThunk + sizeof(uint64_t) * j)) {
				a.dd(offset + (pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfImage - Imports.At(i).FirstThunk - sizeof(uint64_t) * j));
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
			IMAGE_IMPORT_DESCRIPTOR descriptor = Imports.At(i);
			char* name = pOriginal->ReadRVAString(descriptor.Name);
			if (!name) {
				LOG(Failed, MODULE_PACKER, "Failed to read name of imported DLL.\n");
				return buf;
			}
			if (ShellcodeData.RequestedFunctions.iIndex != i) a.embed(name, lstrlenA(name) + 1);
			ZeroMemory(name, lstrlenA(name));
			uint64_t rva = 0;
			while ((rva = pOriginal->ReadRVA<uint64_t>(Imports.At(i).OriginalFirstThunk + sizeof(uint64_t) * j))) {
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
						a.embed(&Sha256Str(name), sizeof(Sha256Digest));
					} else {
						RequestedFunction* pRequest = NULL;
						
						// Get request name
#define CHECK_IMPORT(_name) else if (!lstrcmpA(name, #_name)) pRequest = &ShellcodeData.RequestedFunctions._name
						if (!lstrcmpA(name, "CheckForDebuggers")) pRequest = &ShellcodeData.RequestedFunctions.CheckForDebuggers;
						CHECK_IMPORT(GetSelf);
						CHECK_IMPORT(YAP_NtDelayExecution);
						CHECK_IMPORT(YAP_NtFreeVirtualMemory);
						CHECK_IMPORT(YAP_NtAllocateVirtualMemory);
						CHECK_IMPORT(YAP_NtGetContextThread);
						CHECK_IMPORT(YAP_NtGetNextProcess);
						CHECK_IMPORT(YAP_NtGetNextThread);
						CHECK_IMPORT(YAP_NtOpenProcess);
						CHECK_IMPORT(YAP_NtOpenThread);
						CHECK_IMPORT(YAP_NtProtectVirtualMemory);
						CHECK_IMPORT(YAP_NtReadVirtualMemory);
						CHECK_IMPORT(YAP_NtResumeThread);
						CHECK_IMPORT(YAP_NtResumeProcess);
						CHECK_IMPORT(YAP_NtSetContextThread);
						CHECK_IMPORT(YAP_NtSetInformationProcess);
						CHECK_IMPORT(YAP_NtSetInformationThread);
						CHECK_IMPORT(YAP_NtSetThreadExecutionState);
						CHECK_IMPORT(YAP_NtSuspendProcess);
						CHECK_IMPORT(YAP_NtSuspendThread);
						CHECK_IMPORT(YAP_NtTerminateProcess);
						CHECK_IMPORT(YAP_NtTerminateThread);
						CHECK_IMPORT(YAP_NtWriteVirtualMemory);
						CHECK_IMPORT(YAP_NtClose);
						CHECK_IMPORT(YAP_NtCreateThread);
						CHECK_IMPORT(YAP_GetCurrentThread);
						CHECK_IMPORT(YAP_GetCurrentThreadId);
						CHECK_IMPORT(YAP_GetCurrentProcessId);
						CHECK_IMPORT(YAP_GetCurrentProcess);
						else LOG(Warning, MODULE_PACKER, "Unrecognized SDK import: \'%s\'\n", name);
#undef CHECK_IMPORT

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
				pOriginal->WriteRVA<uint64_t>(Imports.At(i).OriginalFirstThunk + sizeof(uint64_t) * j, 0);
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(rsi, rax);
		a.lea(rdi, ptr(import_offsets));
		if (!::Options.Packing.bHideIAT) a.mov(r13, rdi);
		else a.lea(r13, ptr(import_jumpers));
		a.lea(r12, ptr(import_names));
		a.mov(r14, 0);

		Label do_item = a.newLabel();
		Label do_lib = a.newLabel();
		Label next = a.newLabel();
		Label done = a.newLabel();
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
		a.mov(rdx, r12);
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		if (!::Options.Packing.bHideIAT) {
			a.mov(r8, r13);
			a.sub(r8, r15);
			a.mov(qword_ptr(r8), rax);
		} else {
			a.mov(qword_ptr(r13, 6), rax);
			a.lea(r8, ptr(import_offsets));
			a.sub(r8, r15);
			a.mov(qword_ptr(r8), r13);
			a.add(r13, 14);
		}
		a.add(r12, sizeof(Sha256Digest));
		a.jmp(next);

		Label next_name = a.newLabel();
		a.bind(do_lib);
		a.mov(rcx, r12);
		a.call(rsi);
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
	pOriginal->RebaseImage(pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase + ShellcodeData.OldPENewBaseRVA - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);

	// Handle PEs relocations
	if (!(pOriginal->GetNtHeaders()->x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		Vector<DWORD> Relocations = pOriginal->GetRelocations();

		if (Relocations.Size()) {
			Label skipdata = a.newLabel();
			Label data = a.newLabel();
			a.jmp(skipdata);

			a.bind(data);
			for (int i = 0; i < Relocations.Size(); i++) {
				a.dd(Relocations.At(i));
			}
			a.dd(0);

			WORD nOff = 0;
			a.bind(skipdata);
			a.mov(rcx, pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);
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
		zero.u64Size = pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[5].Size;
		zero.pBytes = reinterpret_cast<BYTE*>(malloc(zero.u64Size));
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[5].VirtualAddress, zero.pBytes, zero.u64Size);
		free(zero.pBytes);
		pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[5].VirtualAddress = pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[5].Size = 0;
	}

	// Load SDK
#define LOAD_IMPORT(name) if (ShellcodeData.RequestedFunctions.name.bRequested) { a.lea(rax, ptr(ShellcodeData.RequestedFunctions.name.Func)); a.mov(rcx, pPackedBinary->GetBaseAddress() + ShellcodeData.OldPENewBaseRVA - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders + ShellcodeData.RequestedFunctions.name.dwRVA); a.add(rcx, ptr(InternalRelOff)); a.mov(qword_ptr(rcx), rax); }
	LOAD_IMPORT(CheckForDebuggers);
	LOAD_IMPORT(GetSelf);
	LOAD_IMPORT(YAP_NtDelayExecution);
	LOAD_IMPORT(YAP_NtFreeVirtualMemory);
	LOAD_IMPORT(YAP_NtAllocateVirtualMemory);
	LOAD_IMPORT(YAP_NtGetContextThread);
	LOAD_IMPORT(YAP_NtGetNextProcess);
	LOAD_IMPORT(YAP_NtGetNextThread);
	LOAD_IMPORT(YAP_NtOpenProcess);
	LOAD_IMPORT(YAP_NtOpenThread);
	LOAD_IMPORT(YAP_NtProtectVirtualMemory);
	LOAD_IMPORT(YAP_NtReadVirtualMemory);
	LOAD_IMPORT(YAP_NtResumeThread);
	LOAD_IMPORT(YAP_NtResumeProcess);
	LOAD_IMPORT(YAP_NtSetContextThread);
	LOAD_IMPORT(YAP_NtSetInformationProcess);
	LOAD_IMPORT(YAP_NtSetInformationThread);
	LOAD_IMPORT(YAP_NtSetThreadExecutionState);
	LOAD_IMPORT(YAP_NtSuspendProcess);
	LOAD_IMPORT(YAP_NtSuspendThread);
	LOAD_IMPORT(YAP_NtTerminateProcess);
	LOAD_IMPORT(YAP_NtTerminateThread);
	LOAD_IMPORT(YAP_NtWriteVirtualMemory);
	LOAD_IMPORT(YAP_NtClose);
	LOAD_IMPORT(YAP_NtCreateThread);
	LOAD_IMPORT(YAP_GetCurrentThread);
	LOAD_IMPORT(YAP_GetCurrentThreadId);
	LOAD_IMPORT(YAP_GetCurrentProcess);
	LOAD_IMPORT(YAP_GetCurrentProcessId);
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
			a.mov(rcx, pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase);
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
		zero.u64Size = pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[9].Size;
		zero.pBytes = reinterpret_cast<BYTE*>(malloc(zero.u64Size));
		ZeroMemory(zero.pBytes, zero.u64Size);
		pOriginal->WriteRVA(pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[9].VirtualAddress, zero.pBytes, zero.u64Size);
		free(zero.pBytes);
		pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[9].VirtualAddress = pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[9].Size = 0;
	}

	// Run main entry point (if applicable)
	if (pOriginal->GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint) {
		a.mov(rax, pOriginal->GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint + ShellcodeData.OldPENewBaseRVA + pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders);
		a.add(rax, ptr(InternalRelOff));
		if (::Options.Packing.EncodingCounts > 1) {
			a.xor_(al, al);
			a.strict();
		}
		a.call(rax);
		a.garbage();
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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
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

	// Sha256
	#include "SHA256.raw"

	// GetProcAddressA
	{
		// Labels
		Label loop = a.newLabel();
		Label strcmp_loop = a.newLabel();
		Label found = a.newLabel();
		Label bad = a.newLabel();
		Label ret = a.newLabel();
		a.bind(ShellcodeData.Labels.GetProcAddressA);

		// Asm
		a.desync();
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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
		a.mov(eax, 0);
		a.bind(ret);
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
		DEBUG_ONLY(if (::Options.Debug.bGenerateBreakpoints) a.int3());
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
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.mov(r12, rax);
		a.pop(rcx);
		a.lea(rdx, ptr(LLA));
		a.call(ShellcodeData.Labels.GetProcAddressA);
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
		a.lea(rcx, ptr(blank));
		a.sub(rsp, 0x20);
		a.call(r13);
		a.add(rsp, 0x20);
		a.mov(rcx, rax);
		a.pop(rdx);
		a.sub(rsp, 0x20);
		a.call(r12);
		a.add(rsp, 0x20);
		a.pop(r15);
		a.pop(r14);
		a.pop(r13);
		a.pop(r12);
		a.jmp(ret);
	}

	// CheckForDebuggers
	if (ShellcodeData.RequestedFunctions.CheckForDebuggers.bRequested) {
		CONTEXT context = { 0 };
		context.ContextFlags = CONTEXT_ALL;
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

		Label ret = a.newLabel();

		a.bind(ShellcodeData.RequestedFunctions.CheckForDebuggers.Func);
		a.push(rsi);

		// PEB check
		a.mov(rax, 0);
		a.mov(rcx, PEB);
		a.mov(al, byte_ptr(rcx, 0x02));
		a.mov(rdx, 0xBC);
		a.mov(r9, 0x70);
		a.mov(r8d, dword_ptr(rcx, rdx));
		a.and_(r8, r9);
		a.xor_(r8, r9);
		a.strict();
		a.setz(al);
		a.strict();
		a.jz(ret);

		// HWBP check
		a.lea(rcx, ptr(NTD));
		a.call(ShellcodeData.Labels.GetModuleHandleW);
		a.mov(rcx, rax);
		a.lea(rdx, ptr(GCT));
		a.call(ShellcodeData.Labels.GetProcAddressA);
		a.test(rax, rax);
		a.strict();
		a.jz(ret);
		a.mov(::Options.Packing.bDirectSyscalls ? r10 : rcx, 0xFFFFFFFFFFFFFFFE);
		a.lea(rdx, ptr(Context));
		a.mov(rsi, rdx);
		if (::Options.Packing.bDirectSyscalls) {
			a.mov(ecx, ptr(rax));
			a.cmp(ecx, 0xB8D18B4C);
			a.strict();
			a.mov(rcx, 1);
			a.strict();
			a.cmovnz(rax, rcx);
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
		a.bind(ret);
		a.pop(rsi);
		a.ret();
	}

	// NTDLL thingies
#define CODE_IMPORT(name) if (ShellcodeData.RequestedFunctions.YAP_##name.bRequested) { Label next = a.newLabel(); Label NTD = a.newLabel(); a.bind(NTD); a.embed(&Sha256WStr(L"ntdll.dll"), sizeof(Sha256Digest)); Label FNN = a.newLabel(); a.bind(FNN); a.embed(&Sha256Str(#name), sizeof(Sha256Digest)); Label RTA = a.newLabel(); a.bind(RTA); a.dq(rand64()); Label NotFound = a.newLabel(); a.bind(ShellcodeData.RequestedFunctions.YAP_##name.Func); a.pop(qword_ptr(RTA)); a.push(rcx); a.push(rdx); a.push(r8); a.push(r9); a.lea(rcx, ptr(NTD)); a.call(ShellcodeData.Labels.GetModuleHandleW); a.mov(rcx, rax); a.lea(rdx, ptr(FNN)); a.call(ShellcodeData.Labels.GetProcAddressA); a.test(rax, rax); a.strict(); a.jz(NotFound); a.pop(r9); a.pop(r8); a.pop(rdx); a.mov(ecx, ptr(rax)); a.mov(r11, 0); a.cmp(ecx, 0xB8D18B4C); a.strict(); a.lea(rcx, ptr(next)); a.strict(); a.cmovne(rcx, r11); a.jmp(rcx); a.bind(next); a.mov(eax, ptr(rax, 4)); a.pop(r10); a.syscall(); a.jmp(qword_ptr(RTA)); a.bind(NotFound); a.mov(rax, 0xC0000225); a.jmp(qword_ptr(RTA)); }
	CODE_IMPORT(NtDelayExecution);
	CODE_IMPORT(NtFreeVirtualMemory);
	CODE_IMPORT(NtAllocateVirtualMemory);
	CODE_IMPORT(NtGetContextThread);
	CODE_IMPORT(NtGetNextProcess);
	CODE_IMPORT(NtGetNextThread);
	CODE_IMPORT(NtOpenProcess);
	CODE_IMPORT(NtOpenThread);
	CODE_IMPORT(NtProtectVirtualMemory);
	CODE_IMPORT(NtReadVirtualMemory);
	CODE_IMPORT(NtResumeThread);
	CODE_IMPORT(NtResumeProcess);
	CODE_IMPORT(NtSetContextThread);
	CODE_IMPORT(NtSetInformationProcess);
	CODE_IMPORT(NtSetInformationThread);
	CODE_IMPORT(NtSetThreadExecutionState);
	CODE_IMPORT(NtSuspendProcess);
	CODE_IMPORT(NtSuspendThread);
	CODE_IMPORT(NtTerminateProcess);
	CODE_IMPORT(NtTerminateThread);
	CODE_IMPORT(NtWriteVirtualMemory);
	CODE_IMPORT(NtClose);
	CODE_IMPORT(NtCreateThread);
#undef CODE_IMPORT

	// YAP_GetCurrentThread
	if (ShellcodeData.RequestedFunctions.YAP_GetCurrentThread.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.YAP_GetCurrentThread.Func);
		a.mov(rax, 0xFFFFFFFFFFFFFFFE);
		a.ret();
	}

	// YAP_GetCurrentThreadId
	if (ShellcodeData.RequestedFunctions.YAP_GetCurrentThreadId.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.YAP_GetCurrentThreadId.Func);
		Mem TEB = qword_ptr(0x30);
		TEB.setSegment(gs);
		a.mov(rax, TEB);
		a.mov(eax, dword_ptr(rax, 0x48));
		a.ret();
	}

	// YAP_GetCurrentProcess
	if (ShellcodeData.RequestedFunctions.YAP_GetCurrentProcess.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.YAP_GetCurrentProcess.Func);
		a.mov(rax, 0xFFFFFFFFFFFFFFFF);
		a.ret();
	}
	
	// YAP_GetCurrentProcessId
	if (ShellcodeData.RequestedFunctions.YAP_GetCurrentProcessId.bRequested) {
		a.bind(ShellcodeData.RequestedFunctions.YAP_GetCurrentProcessId.Func);
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

	// Return data
	holder.flatten();
	holder.relocateToBase(pPackedBinary->GetBaseAddress() + ShellcodeData.BaseAddress);
	LOG(Info, MODULE_PACKER, "Internal code %s relocations\n", holder.hasRelocEntries() ? "contains" : "does not contain");
	ShellcodeData.LoadedOffset = holder.labelOffsetFromBase(entrypt) + holder.baseAddress();
	if (holder.hasRelocEntries()) {
		for (int i = 0; i < holder.relocEntries().size(); i++) {
			if (holder.relocEntries().at(i)->_relocType == RelocType::kNone) continue;
			ShellcodeData.Relocations.Relocations.Push(holder.baseAddress() + holder.relocEntries().at(i)->sourceOffset() - pPackedBinary->GetNtHeaders()->x64.OptionalHeader.ImageBase);
		}
	}

	buf.u64Size = holder.textSection()->buffer().size();
	buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
	memcpy(buf.pBytes, holder.textSection()->buffer().data(), buf.u64Size);
	LOG(Success, MODULE_PACKER, "Generated internal shellcode\n");
	return buf;
}

bool Pack(_In_ PE* pOriginal, _In_ PackerOptions Options, _Out_ PE* pPackedBinary) {
	// Argument validation
	if (!pOriginal || !pPackedBinary) {
		LOG(Failed, MODULE_PACKER, "Invalid arguments\n");
		return false;
	}
	if (!(pOriginal->GetNtHeaders()->x64.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) || (pOriginal->GetNtHeaders()->x64.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)) {
		LOG(Failed, MODULE_PACKER, "Binary must be relocatable to be packed\n");
		return false;
	}

	srand(GetTickCount64());
	ShellcodeData.EntryOff = 0x30 + rand() & 0xCF;

	if (::Options.Packing.EncodingCounts > 1) {
#ifdef _DEBUG
		if (::Options.Debug.bDisableRelocations) {
			LOG(Failed, MODULE_PACKER, "Relocations must be enabled to pack multiple times\n");
			return false;
		}
#endif
		Options_t OptionsBackup = ::Options;
		char* MessageBackup = Options.Message;
		Options.Message = NULL;
		::Options.Packing.Message[0] = 0;
		::Options.Packing.bFalseSymbols = false;
		::Options.Packing.Immitate = YAP;
		::Options.Packing.bAntiDebug = false;
		::Options.Packing.bAntiSandbox = false;
		::Options.Packing.bAntiVM = false;
		::Options.Packing.bAntiDump = false;
		::Options.Packing.bDelayedEntry = false;
		::Options.Packing.bMitigateSideloading = false;
		::Options.Packing.bOnlyLoadMicrosoft = false;
		Asm* dupe = new Asm();
		::Options.Packing.EncodingCounts--;
		if (!Pack(pOriginal, Options, dupe)) {
			LOG(Failed, MODULE_PACKER, "Packing at depth %i failed\n", ::Options.Packing.EncodingCounts);
			delete dupe;
			return false;
		}
		ZeroMemory(&ShellcodeData, sizeof(_ShellcodeData));
		ShellcodeData.RequestedFunctions.iIndex = -1;
		LOG(Success, MODULE_PACKER, "Packed at depth %i\n", ::Options.Packing.EncodingCounts);
		Options.bVM = false;
		Options.sMasqueradeAs = NULL;
		Options.Message = MessageBackup;
		::Options = OptionsBackup;
		pOriginal = dupe;
	} else {
		AesGenTables();
		Sha256Prepare();
	}

	// Setup DOS header & stub (e_lfanew is managed by PE)
	if (true) {
		pPackedBinary->GetDosStub()->u64Size = pOriginal->GetDosStub()->u64Size;
		pPackedBinary->GetDosStub()->pBytes = reinterpret_cast<BYTE*>(malloc(pPackedBinary->GetDosStub()->u64Size));
		memcpy(pPackedBinary->GetDosStub()->pBytes, pOriginal->GetDosStub()->pBytes, pOriginal->GetDosStub()->u64Size);
	}
	pPackedBinary->GetDosHeader()->e_magic = IMAGE_DOS_SIGNATURE;
	pPackedBinary->GetDosHeader()->e_lfanew = sizeof(IMAGE_DOS_HEADER) + pPackedBinary->GetDosStub()->u64Size;

	// Save resources
	Buffer resources = { 0 };
	if (::Options.Packing.bDontCompressRsrc && pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].Size && pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].VirtualAddress) {
		IMAGE_DATA_DIRECTORY rsrc = pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2];
		IMAGE_SECTION_HEADER* pHeader = pOriginal->GetSectionHeader(pOriginal->FindSectionByRVA(rsrc.VirtualAddress));
		Buffer raw = pOriginal->GetSectionBytes(pOriginal->FindSectionByRVA(rsrc.VirtualAddress));
		if (!pHeader || !raw.pBytes || !raw.u64Size) {
			LOG(Warning, MODULE_PACKER, "A resource section was present, but resources could not be read! (RVA: %x)\n", rsrc.VirtualAddress);
		} else {
			resources.pBytes = reinterpret_cast<BYTE*>(malloc(resources.u64Size = rsrc.Size));
			memcpy(resources.pBytes, raw.pBytes + rsrc.VirtualAddress - pHeader->VirtualAddress, resources.u64Size);
			ZeroMemory(raw.pBytes + rsrc.VirtualAddress - pHeader->VirtualAddress, resources.u64Size);
		}
	}

	// NT headers
	bool bIsDLL = pOriginal->GetNtHeaders()->x64.FileHeader.Characteristics & IMAGE_FILE_DLL;
	IMAGE_NT_HEADERS64* pNT = &pPackedBinary->GetNtHeaders()->x64;
	pNT->Signature = IMAGE_NT_SIGNATURE;
	pNT->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	pNT->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
	pNT->FileHeader.Characteristics = (bIsDLL ? IMAGE_FILE_DLL : 0) | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED;
	DEBUG_ONLY(if (::Options.Debug.bDisableRelocations) pNT->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED);
	pNT->OptionalHeader.Magic = 0x20B;
	pNT->OptionalHeader.SectionAlignment = 0x1000;
	pNT->OptionalHeader.FileAlignment = 0x200;
	ShellcodeData.ImageBase = pNT->OptionalHeader.ImageBase = bIsDLL ? 0x10000000 : 0x140000000;
	pNT->OptionalHeader.MajorOperatingSystemVersion = 4;
	pNT->OptionalHeader.MajorSubsystemVersion = 6;
	pNT->OptionalHeader.SizeOfHeaders = pPackedBinary->GetDosHeader()->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER);
	pNT->OptionalHeader.SizeOfHeaders += (pNT->OptionalHeader.SizeOfHeaders % 0x200) ? 0x200 - (pNT->OptionalHeader.SizeOfHeaders % 0x200) : 0;
	pNT->OptionalHeader.Subsystem = pOriginal->GetNtHeaders()->x64.OptionalHeader.Subsystem;
	pNT->OptionalHeader.NumberOfRvaAndSizes = 0x10;
	pNT->OptionalHeader.SizeOfStackReserve = 0x200000;
	pNT->OptionalHeader.SizeOfHeapReserve = 0x100000;
	pNT->OptionalHeader.SizeOfHeapCommit = pNT->OptionalHeader.SizeOfStackCommit = 0x1000;
	if (::Options.Packing.Immitate == UPX) {
		pNT->FileHeader.NumberOfSymbols = 0x21585055; // UPX!
		pNT->FileHeader.PointerToSymbolTable = 0x0034322E; // .24
		pNT->FileHeader.TimeDateStamp = 0x34000000; // 4
	}
	pNT->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
	DEBUG_ONLY(if (::Options.Debug.bDisableRelocations) pNT->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	// Section header
	IMAGE_SECTION_HEADER SecHeader = { 0 };
	SecHeader.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	SecHeader.VirtualAddress = pNT->OptionalHeader.SizeOfHeaders;
	SecHeader.VirtualAddress += (SecHeader.VirtualAddress % 0x1000) ? 0x1000 - (SecHeader.VirtualAddress % 0x1000) : 0;
	ShellcodeData.OldPENewBaseRVA = SecHeader.VirtualAddress;
	ShellcodeData.BaseAddress = ShellcodeData.OldPENewBaseRVA + pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfImage - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders;
	ShellcodeData.bUsingTLSCallbacks = ::Options.Packing.bDelayedEntry || ::Options.Packing.bAntiDebug || (pOriginal->GetTLSCallbacks() && *pOriginal->GetTLSCallbacks());
	Buffer Internal = GenerateInternalShellcode(pOriginal, Options, pPackedBinary);
	if (!Internal.u64Size || !Internal.pBytes) {
		LOG(Failed, MODULE_PACKER, "Failed to generate internal shellcode!\n");
		return false;
	}
	SecHeader.Misc.VirtualSize = Internal.u64Size + pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfImage - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders;
	switch (::Options.Packing.Immitate) {
	case Themida:
		memcpy(SecHeader.Name, ".themida", 8);
		break;
	case WinLicense:
		memcpy(SecHeader.Name, ".winlice", 8);
		break;
	case UPX:
		memcpy(SecHeader.Name, "UPX0\0", 8);
		break;
	case MPRESS:
		memcpy(SecHeader.Name, ".MPRESS1\0", 8);
		break;
	case Enigma:
		memcpy(SecHeader.Name, ".enigma1", 8);
		break;
	default:
		memcpy(SecHeader.Name, &ValidSectionNames[(rand() % (sizeof(ValidSectionNames) / 8)) * 8], 8);
	}
	pPackedBinary->InsertSection(0, NULL, SecHeader);
	SecHeader.VirtualAddress += SecHeader.Misc.VirtualSize;
	SecHeader.VirtualAddress += (SecHeader.VirtualAddress % 0x1000) ? 0x1000 - (SecHeader.VirtualAddress % 0x1000) : 0;
	ShellcodeData.BaseAddress = SecHeader.VirtualAddress;
	switch (::Options.Packing.Immitate) {
	case Themida:
		memcpy(SecHeader.Name, "Themida", 8);
		break;
	case WinLicense:
		memcpy(SecHeader.Name, "WinLicen", 8);
		break;
	case UPX:
		memcpy(SecHeader.Name, "UPX1", 8);
		break;
	case MPRESS:
		memcpy(SecHeader.Name, ".MPRESS2", 8);
		break;
	case Enigma:
		memcpy(SecHeader.Name, ".enigma2", 8);
		break;
	default:
		memcpy(SecHeader.Name, &ValidSectionNames[(rand() % (sizeof(ValidSectionNames)) / 8) * 8], 8);
	}
	pNT->OptionalHeader.AddressOfEntryPoint = SecHeader.VirtualAddress;

	// Get shellcode
	Buffer shell = GenerateLoaderShellcode(pOriginal, Options, pPackedBinary, Internal);
	free(Internal.pBytes);
	if (!shell.pBytes || !shell.u64Size) {
		LOG(Failed, MODULE_PACKER, "Failed to generate loader shellcode!\n");
		return false;
	}

	// TLS callback
	IMAGE_TLS_DIRECTORY64 TLSDataDir = { 0 };
	int nTLSEntries = 0;
	if (ShellcodeData.bUsingTLSCallbacks) {
		// Gen num of TLS
		int nFalseEntries = 0;
		nTLSEntries = 1;
		if (::Options.Packing.bAntiDebug) {
			nFalseEntries = 3 + rand() % 5;
			nTLSEntries = nFalseEntries + 1;
		}

		pNT->OptionalHeader.DataDirectory[9].Size = sizeof(IMAGE_TLS_DIRECTORY64);
		pNT->OptionalHeader.DataDirectory[9].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;
		ShellcodeData.BaseAddress = SecHeader.VirtualAddress + shell.u64Size + sizeof(IMAGE_TLS_DIRECTORY64) + sizeof(uint64_t) * (nTLSEntries + 1);
		Buffer TLSCode = GenerateTLSShellcode(Options, pPackedBinary, pOriginal);
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
			pEntries[i] = pPackedBinary->GetBaseAddress() + SecHeader.VirtualAddress + shell.u64Size + resources.u64Size + pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[0].Size + 0x10000 + rand();
		}

		free(TLSCode.pBytes);
	}

	// Relocations
#ifdef _DEBUG
	if (!::Options.Debug.bDisableRelocations) {
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
	if (::Options.Packing.bDontCompressRsrc && resources.pBytes && resources.u64Size) {
		pPackedBinary->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].Size = resources.u64Size;
		pPackedBinary->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].VirtualAddress = SecHeader.VirtualAddress + shell.u64Size;

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
					pResource->OffsetToData += pPackedBinary->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].VirtualAddress - pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[2].VirtualAddress;
				}
			}
		} while (Offsets.Size());

		shell.Merge(resources);
	}

	// Exports
	if (pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[0].VirtualAddress && pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[0].Size) {
		IMAGE_EXPORT_DIRECTORY Exports = { 0 };
		IMAGE_EXPORT_DIRECTORY OriginalExports = pOriginal->ReadRVA<IMAGE_EXPORT_DIRECTORY>(pOriginal->GetNtHeaders()->x64.OptionalHeader.DataDirectory[0].VirtualAddress);
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
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (exports.Size() - i)) = exports.At(i) + ShellcodeData.OldPENewBaseRVA - pOriginal->GetNtHeaders()->x64.OptionalHeader.SizeOfHeaders;
		}

		// Export names
		shell.u64Size += names.Size() * sizeof(DWORD);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		DWORD rva = Exports.AddressOfNameOrdinals + sizeof(WORD) * names.Size();
		for (int i = 0; i < names.Size(); i++) {
			*reinterpret_cast<DWORD*>(shell.pBytes + shell.u64Size - sizeof(DWORD) * (names.Size() - i)) = rva;
			rva += lstrlenA(names.At(i)) + 1;
		}

		// Export ordinals
		shell.u64Size += names.Size() * sizeof(WORD);
		shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
		for (WORD i = 0; i < names.Size(); i++) {
			*reinterpret_cast<WORD*>(shell.pBytes + shell.u64Size - sizeof(WORD) * (names.Size() - i)) = i;
		}

		// Export names
		for (int i = 0; i < names.Size(); i++) {
			int len = lstrlenA(names.At(i)) + 1;
			shell.u64Size += len;
			shell.pBytes = reinterpret_cast<BYTE*>(realloc(shell.pBytes, shell.u64Size));
			memcpy(shell.pBytes + shell.u64Size - len, names.At(i), len);
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
	if (::Options.Packing.bDelayedEntry) pPackedBinary->GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint = pPackedBinary->GetSectionHeaders()[0].VirtualAddress;

	// MPRESS stuff
	if (::Options.Packing.Immitate == MPRESS) {
		memcpy(((BYTE*)pPackedBinary->GetDosHeader()) + 0x2E, "Win64 .EXE.\r\n", 13);
	}

	// Fake data
	if (::Options.Packing.bFalseSymbols) {
		pNT->OptionalHeader.DataDirectory[10].VirtualAddress = SecHeader.VirtualAddress; // Load config directory
		pNT->OptionalHeader.DataDirectory[10].Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64);
		pNT->OptionalHeader.DataDirectory[6].VirtualAddress = SecHeader.VirtualAddress + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64); // Debug directory
		pNT->OptionalHeader.DataDirectory[6].Size = sizeof(IMAGE_DEBUG_DIRECTORY);
		if (::Options.Packing.Immitate != UPX) {
			pNT->FileHeader.PointerToSymbolTable = SecHeader.PointerToRawData + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64) + sizeof(IMAGE_DEBUG_DIRECTORY);
			pNT->FileHeader.NumberOfSymbols = rand();
		}
	}

	if (::Options.Packing.EncodingCounts > 1) {
		delete pOriginal;
	}
	pPackedBinary->OverrideStatus(Normal);

	return true;
}


/***** ProtectedAssembler functions *****/

int ProtectedAssembler::randstack(_In_ int nMin, _In_ int nMax) {
	if (nMin > nMax) return 0;
	HeldLocks++;
	Gp temp;
	int n = nMin == nMax ? nMin : nMin + (rand() % (nMax - nMin));
	int ret = 0;
	for (int i = 0; i < n; i++) {
		// Select register
		do {
			temp = truerandreg();
		} while (stack.Size() < countof(regs) - Blacklist.Size() && (stack.Includes(temp) || Blacklist.Includes(temp.r64())));
		if (stack.Includes(temp) || Blacklist.Includes(temp.r64())) break;
		push(temp);
		stack.Push(temp);
		ret++;

		// Random push
		if (rand() & 1) {
			for (int j = 0, m = 5; j < m; j++) {
				temp = randreg();
				if (temp.size() == 8) {
					stack.Push(temp);
					ret++;
					push((rand() & 1) ? 0 : rand());
					break;
				}
			}
		}

		// Random math again
		for (int j = rand() % Options.Packing.MutationLevel; j; j--) {
			randinst(randreg());
		}
	}
	HeldLocks--;
	return ret;
}

void ProtectedAssembler::restorestack(_In_ int n) {
	if (!stack.Size()) return;
	HeldLocks++;
	if (n < 0) {
		while (stack.Size()) {
			// Restore register
			pop(stack.Pop());

			for (int j = rand() % Options.Packing.MutationLevel; j; j--) {
				randinst(randreg());
			}
		}
		stack.Release();
	} else {
		for (int i = 0; i < n; i++) {
			pop(stack.Pop());

			for (int j = rand() % Options.Packing.MutationLevel; j; j--) {
				randinst(randreg());
			}
		}
	}
	HeldLocks--;
}

void ProtectedAssembler::randinst(Gp o0) {
	if (!stack.Includes(o0) || Blacklist.Includes(o0.r64()) || Blacklist.Includes(o0) || o0.size() != 8) return;
	HeldLocks++;
	const BYTE sz = 26;
	const BYTE beg_unsafe = 12;
	BYTE end = bStrict ? beg_unsafe : sz;
	Mem peb = ptr(0x60);
	peb.setSegment(gs);
	switch (rand() % end) {
	case 0:
		lea(o0, ptr(rip, rand()));
		break;
	case 1:
		lea(o0, ptr(truerandreg(), (rand() & 1 ? 1 : -1) * rand()));
		break;
	case 2:
		lea(o0, ptr(truerandreg(), truerandreg(), rand() % 3));
		break;
	case 3:
		lea(o0, ptr(truerandreg(), truerandreg(), rand() % 3, (rand() & 1 ? 1 : -1) * rand()));
		break;
	case 4: {
		BYTE r = 3 + rand() % (Options.Packing.MutationLevel * 2);
		Label j2 = newLabel();
		jmp(j2);
		for (; r > 0; r--) db(rand() & 0xFF);
		bind(j2);
		break;
	}
	case 5:
		mov(o0, 0);
		break;
	case 6:
		mov(o0, rand());
		break;
	case 7:
		mov(o0, ptr(rsp, rand() % 32));
		break;
	case 8:
		mov(o0, peb);
		break;
	case 9: {
		BYTE r = 3 + rand() % (Options.Packing.MutationLevel * 2);
		Label j2 = newLabel();
		jbe(j2);
		jnc(j2);
		for (; r > 0; r--) db(rand() & 0xFF);
		bind(j2);
		break;
	}
	case 10: {
		bool bNeedsValid = false;
		BYTE valid[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x64, 0x65, 0x66, 0x67, 0x2E, 0x3E, 0xF2, 0xF3 };
		for (int i = 0, n = 1 + rand() % 14; i < n; i++) {
			BYTE selected = valid[rand() % sizeof(valid)];
			if (selected == 0x41 || selected == 0x43 || selected == 0x45 || selected == 0x47 || selected == 0x49 || selected == 0x4B || selected == 0x4D) {
				// Try again
				if (i == 13) { i--; continue; }
				
				// Make room for validating prefix
				if (!bNeedsValid) n--;
				bNeedsValid = true;
			}
			db(selected);
		}
		if (bNeedsValid) {
			BYTE validators[] = { 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E };
			db(validators[rand() % sizeof(validators)]);
		}
		db(0x90);
		break;
	}
	case 11: // In IDA these disassemble as the same instruction, but function differently ;)
		if (o0.r64() == rax.r64()) {
			block();
			xchg(eax, eax);
		} else {
			db(0x46);
			db(0x90);
		}
		break;
	//case 11:
		//desync_mov(o0.r64()); // This is VERY slow for some reason
		//break;

	// Unsafe instructions
	/*case 9:
		inc(randsize(o0));
		break;
	case 10:
		dec(randsize(o0));
		break;
	case 11:
		add(randsize(o0), rand());
		break;
	case 12:
		o0 = randsize(o0);
		add(o0, randregofsamesize(o0));
		break;
	case 13:
		sub(randsize(o0), rand());
		break;
	case 14:
		o0 = randsize(o0);
		sub(o0, randregofsamesize(o0));
		break;
	case 15:
		xor_(randsize(o0), rand());
		break;
	case 16:
		o0 = randsize(o0);
		xor_(o0, randregofsamesize(o0));
		break;
	case 17:
		or_(randsize(o0), rand());
		break;
	case 18:
		o0 = randsize(o0);
		or_(o0, randregofsamesize(o0));
		break;
	case 19:
		if (stack.Includes(rax)) desync();
		break;
	case 20:
		not_(randsize(o0));
		break;
	case 21:
		and_(randsize(o0), rand());
		break;
	case 22:
		o0 = randsize(o0);
		and_(o0, randregofsamesize(o0));
		break;
	case 23:
		cmp(randsize(o0), rand());
		break;
	case 24:
		o0 = randsize(o0);
		cmp(o0, randregofsamesize(o0));
		break;
	case 25:
		o0 = randsize(o0);
		test(o0, o0);
		break;*/
	}
	HeldLocks--;
}

// Everything in this stub needs to be blocked otherwise it will cause an infinite loop
void ProtectedAssembler::stub() {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return);
	HeldLocks++;
	DEBUG_ONLY(if (Options.Debug.bGenerateMarks) nop());
	if (stack.Size()) {
		LOG(Warning, MODULE_PACKER, "Stub was requested when stack was not empty, ignoring request.\n");
		return;
	}
	randstack(0, Options.Packing.MutationLevel);
	for (int i = 0, n = rand() % ::Options.Packing.MutationLevel; i < n; i++) randinst(randreg());
	restorestack();
	DEBUG_ONLY(if (Options.Debug.bGenerateMarks) nop());
	HeldLocks--;
}

size_t ProtectedAssembler::garbage() {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return 0);
	DEBUG_ONLY(if (::Options.Debug.bGenerateMarks) { HeldLocks++;  nop(); xchg(rax, rax); HeldLocks--; });
	Label randlabel;
	randlabel = newLabel();
	Gp reg;
	for (int i = 0, n = (1000 / (17 - ::Options.Packing.MutationLevel)) + rand() % (10000 / (17 - ::Options.Packing.MutationLevel)); i < n; i++) {
	retry:
		switch (rand() % 46) {
		case 0:
			inc(randsize(truerandreg()));
			break;
		case 1:
			dec(randsize(truerandreg()));
			break;
		case 2:
			reg = randsize(truerandreg());
			xchg(reg, randregofsamesize(reg));
			break;
		case 3:
			reg = randsize(truerandreg());
			cmp(reg, randregofsamesize(reg));
			break;
		case 4:
			cmp(randsize(truerandreg()), 0);
			break;
		case 5:
			mov(randsize(truerandreg()), rand());
			break;
		case 6:
			mov(randsize(truerandreg()), 0);
			break;
		case 7:
			reg = randsize(truerandreg());
			mov(reg, randregofsamesize(reg));
			break;
		case 8:
			break;
		case 9:
			break;
		case 10:
			desync();
			break;
		case 11:
			desync_mov(truerandreg().r64());
			break;
		case 12:
			jz(randlabel);
			break;
		case 13:
			jnz(randlabel);
			break;
		case 14:
			shl(truerandreg(), rand() % 64);
			break;
		case 15:
			shr(truerandreg(), rand() % 64);
			break;
		case 16:
			//mov(truerandreg(), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			break;
		case 17:
			//lea((reg = truerandreg()), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			//mov(truerandreg(), ptr(reg));
			break;
		case 18:
			//lea((reg = truerandreg()), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			//mov(truerandreg(), ptr(reg, rand()));
			break;
		case 19:
			break;
		case 20:
			break;
		case 21:
			break;
		case 22:
			break;
		case 23:
			break;
		case 24:
			break;
		case 25:
			break;
		case 26:
			reg = randsize(truerandreg());
			test(reg, reg);
			break;
		case 27:
			cmp(randsize(truerandreg()), rand());
			break;
		case 28:
			xor_(randsize(truerandreg()), rand());
			break;
		case 29:
			reg = randsize(truerandreg());
			xor_(reg, randregofsamesize(reg));
			break;
		case 30:
			or_(randsize(truerandreg()), rand());
			break;
		case 31:
			reg = randsize(truerandreg());
			or_(reg, randregofsamesize(reg));
			break;
		case 32:
			not_(randsize(truerandreg()));
			break;
		case 33:
			reg = randsize(truerandreg());
			sub(reg, randregofsamesize(reg));
			break;
		case 34:
			sub(randsize(truerandreg()), rand());
			break;
		case 35:
			reg = randsize(truerandreg());
			add(reg, randregofsamesize(reg));
			break;
		case 36:
			add(randsize(truerandreg()), rand());
			break;
		case 37:
			mul(randsize(truerandreg()));
			break;
		case 38:
			lea(truerandreg(), ptr(truerandreg()));
			break;
		case 39:
			lea(truerandreg(), ptr(truerandreg(), truerandreg()));
			break;
		case 40:
			lea(truerandreg(), ptr(truerandreg(), truerandreg(), rand() % 4, rand()));
			break;
		case 41:
			lea(truerandreg(), ptr(truerandreg(), rand()));
			break;
		default:
			if (!i) goto retry;
			if (!code()->isLabelBound(randlabel)) bind(randlabel);
			randlabel = newLabel();
		}
	}
	DEBUG_ONLY(if (::Options.Debug.bGenerateMarks) { HeldLocks++;  nop(); xchg(rax, rax); HeldLocks--; });
	return 0;
}

void ProtectedAssembler::desync() {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return);
	HeldLocks++;
	db(0xEB);
	block();
	inc(eax);
	HeldLocks--;
}

void ProtectedAssembler::desync_jz() {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return);
	HeldLocks++;
	db(0x74);
	block();
	inc(ebx);
	HeldLocks--;
}

void ProtectedAssembler::desync_jnz() {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return);
	HeldLocks++;
	db(0x75);
	block();
	inc(ebx);
	HeldLocks--;
}

void ProtectedAssembler::desync_mov(Gpq o0) {
	DEBUG_ONLY(if (Options.Debug.bDisableMutations) return);
	uint64_t dist = 3 + rand() % Options.Packing.MutationLevel * 2;
	push((dist << 16) + 0xE940);
	Label after = newLabel();
	lea(o0, ptr(after));
	pop(qword_ptr(o0));
	bind(after);
	for (int i = 0; i < dist + 6; i++) db(rand() & 0xFF);
}

Error ProtectedAssembler::call(Gp o0) {
	return Assembler::call(o0);
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false)) return Assembler::call(o0);
	BYTE dist = 0;
	DEBUG_ONLY(if (!Options.Debug.bDisableMutations)) dist = 64 + (rand() % 192);
	push(o0);
	push(o0);
	push(o0);
	Label after = newLabel();
	lea(o0, ptr(after));
	if (dist) add(o0, dist);
	mov(ptr(rsp, 0x10), o0);
	pop(o0);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::call(Imm o0) {
	return Assembler::call(o0);
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false)) return Assembler::call(o0);
	Gp reg = truerandreg();
	BYTE dist = 0;
	DEBUG_ONLY(if (!Options.Debug.bDisableMutations)) dist = 64 + (rand() % 192);
	push(o0);
	push(o0);
	push(reg);
	Label after = newLabel();
	lea(reg, ptr(after));
	if (dist) add(reg, dist);
	mov(ptr(rsp, 0x10), reg);
	pop(reg);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::call(Label o0) {
	return Assembler::call(o0);
}

Error ProtectedAssembler::call(Mem o0) {
	return Assembler::call(o0);
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false)) return Assembler::call(o0);
	Gp reg = truerandreg();
	o0.setSize(8);
	BYTE dist = 0;
	DEBUG_ONLY(if (!Options.Debug.bDisableMutations)) dist = 64 + (rand() % 192);
	push(o0);
	push(o0);
	push(reg);
	Label after = newLabel();
	lea(reg, ptr(after));
	if (dist) add(reg, dist);
	mov(ptr(rsp, 0x10), reg);
	pop(reg);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::mov(Gp o0, Imm o1) {
	return Assembler::mov(o0, o1);
	if (o0.size() == 4) o0 = o0.r64();
	if (o0.size() == 1) return Assembler::mov(o0, o1);
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false)) return Assembler::mov(o0, o1);
	Blacklist.Push(o0.r64());
	randstack(0, 7);
	block();
	push(o1);
	for (int i = 0, n = o0.size() == 2 ? 4 : 1; i < n; i++) stack.Push(o0);
	Blacklist.Pop();
	randstack(0, 7);
	restorestack();
	return 0;
}

Error ProtectedAssembler::mov(Gp o0, Gp o1) {
	return Assembler::mov(o0, o1);
	if (o0.r64() == rsp || o1.r64() == rsp || bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false) || o0.size() != o1.size()) return Assembler::mov(o0, o1);

	if (o0.size() == 4) { o0 = o0.r64(); o1 = o1.r64(); } // replace this
	if (o0.size() == 1) { o0 = o0.r16(); o1 = o1.r16(); } // this too

	Blacklist.Push(o0.r64());
	Blacklist.Push(o1.r64());
	randstack(0, 7);
	block();
	push(o1);
	Blacklist.Pop();
	Blacklist.Pop();
	stack.Push(o0);
	randstack(0, 7);
	restorestack();
	return 0;
}

Error ProtectedAssembler::mov(Gp o0, Mem o1) {
	return Assembler::mov(o0, o1);
	o1.setSize(o0.size());
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false) || o0.size() == 1 || o0.size() == 4) return Assembler::mov(o0, o1);
	
	randstack(0, 7);
	if (o1.hasBaseReg() && o1.baseReg() == rsp) o1.addOffset(GetStackSize());
	block();
	push(o1);
	stack.Push(o0);
	randstack(0, 7);
	restorestack();
	return 0;
}

Error ProtectedAssembler::mov(Mem o0, Imm o1) {
	return Assembler::mov(o0, o1);
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false) || o0.size() != 8) return Assembler::mov(o0, o1);
	randstack(0, 7);
	block();
	push(o1);
	restorestack(randstack(0, 7));
	if (o0.hasBaseReg() && o0.baseReg() == rsp) o0.addOffset(GetStackSize());
	block();
	pop(o0);
	restorestack();
	return 0;
}

Error ProtectedAssembler::mov(Mem o0, Gp o1) {
	return Assembler::mov(o0, o1);
	o0.setSize(o1.size());
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false) || (o0.size() != 8 && o0.size() != 2)) return Assembler::mov(o0, o1);
	push(o1);
	return pop(o0);
}

Error ProtectedAssembler::movzx(Gp o0, Mem o1) {
	return Assembler::movzx(o0, o1);
	if (o1.hasBaseReg() && o1.baseReg() == rsp) return Assembler::movzx(o0, o1);
	o0 = o0.r64();
	if (bWaitingOnEmit || DEBUG_ONLY(Options.Debug.bDisableMutations) RELEASE_ONLY(false) || o1.size() != 2) return Assembler::movzx(o0, o1);
	push(0);
	pop(o0);
	Gp o16 = o0.r16();
	push(o16);
	push(o16);
	push(o16);
	push(o1);
	return pop(o0);
}

Error ProtectedAssembler::movzx(Gp o0, Gp o1) {
	return Assembler::movzx(o0, o1);
}

Error ProtectedAssembler::_emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) {
	bStrict = true; // temp fix for garbage gen
	if (!bWaitingOnEmit && !HeldLocks && !bUnprotected) { stub(); bStrict = false; }
	else { bWaitingOnEmit = false; }
	return Assembler::_emit(instId, o0, o1, o2, opExt);
}

uint64_t ProtectedAssembler::GetStackSize() {
	uint64_t ret = 0;
	for (int i = 0, n = stack.Size(); i < n; i++) {
		ret += stack.At(i).size();
	}
	return ret;
}

Error ProtectedAssembler::ret() {
	if (stack.Size()) {
		LOG(Warning, MODULE_PACKER, "ret requested when stack isn't clear, clearing stack.\n");
		restorestack();
	}
	return Assembler::ret();
}

Error ProtectedAssembler::ret(Imm o0) {
	if (stack.Size()) {
		LOG(Warning, MODULE_PACKER, "ret requested when stack isn't clear, clearing stack.\n");
		restorestack();
	}
	return Assembler::ret(o0);
}