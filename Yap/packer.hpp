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
	uint64_t TrueEntryOffset = 0;
	uint64_t LoadedOffset = 0;
	uint64_t VMAbs = 0;
	uint64_t ImageBase = 0;
	uint64_t MessageBoxAddr = 0;
	BYTE EntryOff = 0;
	DWORD GetProcAddressAOff = 0;
	DWORD GetModuleHandleWOff = 0;
	bool bUsingTLSCallbacks = false;

	struct {
		Vector<uint64_t> Relocations;
	} Relocations;

	struct {
		Label GetModuleHandleW;
		Label GetProcAddressByOrdinal;
		Label GetProcAddressA;
		Label RtlZeroMemory;
		Label RelocDiff;
	} Labels;

	struct {
		BYTE EncodedProp[LZMA_PROPS_SIZE];
	} UnpackData;

	struct {
		int iIndex = -1;
		RequestedFunction CheckForDebuggers;
		RequestedFunction YAP_NtDelayExecution;
		RequestedFunction YAP_NtFreeVirtualMemory;
		RequestedFunction YAP_NtAllocateVirtualMemory;
		RequestedFunction YAP_NtGetContextThread;
		RequestedFunction YAP_NtGetNextProcess;
		RequestedFunction YAP_NtGetNextThread;
		RequestedFunction YAP_NtOpenProcess;
		RequestedFunction YAP_NtOpenThread;
		RequestedFunction YAP_NtProtectVirtualMemory;
		RequestedFunction YAP_NtReadVirtualMemory;
		RequestedFunction YAP_NtResumeThread;
		RequestedFunction YAP_NtResumeProcess;
		RequestedFunction YAP_NtSetContextThread;
		RequestedFunction YAP_NtSetInformationProcess;
		RequestedFunction YAP_NtSetInformationThread;
		RequestedFunction YAP_NtSetThreadExecutionState;
		RequestedFunction YAP_NtSuspendProcess;
		RequestedFunction YAP_NtSuspendThread;
		RequestedFunction YAP_NtTerminateProcess;
		RequestedFunction YAP_NtTerminateThread;
		RequestedFunction YAP_NtWriteVirtualMemory;
		RequestedFunction YAP_NtClose;
		RequestedFunction YAP_NtCreateThread;
		RequestedFunction YAP_GetCurrentThread;
		RequestedFunction YAP_GetCurrentThreadId;
		RequestedFunction YAP_GetCurrentProcess;
		RequestedFunction YAP_GetCurrentProcessId;
	} RequestedFunctions;
};

struct PackerOptions {
	bool bVM : 1;
	char* Message = NULL;
	char* sMasqueradeAs = NULL;
	Vector<DWORD> VMFuncs;
};

bool Pack(_In_ PE* pOriginal, _In_ PackerOptions Options, _Out_ PE* pPackedBinary);

class ProtectedAssembler : public Assembler {
private:
	bool bWaitingOnEmit = false;
	BYTE HeldLocks = 0;
	bool bStrict = false;
	bool bUnprotected = false;
	Gp regs[15] = { rax, rbx, rcx, rdx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 };
	Vector<Gp> Blacklist;
	Gp truerandreg() { return regs[rand() % countof(regs)]; }
	Gp randsize(Gp o0) {
		switch (rand() % 10) {
		case 0:
			return o0.r8();
		case 1:
			return o0.r16();
		case 2:
		case 3:
		case 4:
			return o0.r32();
		default:
			return o0.r64();
		}
		return o0;
	}
	Gp randregofsamesize(_In_ Gp o0) {
		Gp o1;
		do {
			o1 = truerandreg();
			switch (o0.size()) {
			case 1:
				o1 = o1.r8();
				break;
			case 2:
				o1 = o1.r16();
				break;
			case 4:
				o1 = o1.r32();
				break;
			case 8:
				o1 = o1.r64();
			}
		} while (o1 == o0);
		if (o1.size() != o0.size()) {
			LOG(Warning, "Size mismatch!\n");
		}
		return o1;
	}
	Gp randreg() { return stack.Size() ? stack.At(rand() % stack.Size()) : rsp; }
	Vector<Gp> stack;
	int randstack(_In_ int nMin = 0, _In_ int nMax = 15);
	void restorestack(_In_ int n = -1);
	void randinst(Gp o0);
	uint64_t GetStackSize();

public:
	void stub();
	size_t garbage();
	void desync();
	void desync_jz();
	void desync_jnz();
	void desync_mov(Gpq o0);
	void block() { bWaitingOnEmit = true; } // Prevents garbage stub from being generated
	void strict() { bStrict = true; } // Tells the garbage stub to leave EFLAGS untouched
	void unprotected() { bUnprotected = true; }
	void protect() { bUnprotected = false; }
	Error call(Gp o0);
	Error call(Imm o0);
	Error call(Label o0);
	Error call(Mem o0);
	Error mov(Gp o0, Imm o1);
	Error mov(Gp o0, Gp o1);
	Error mov(Gp o0, Mem o1);
	Error mov(Mem o0, Imm o1);
	Error mov(Mem o0, Gp o1);
	Error movzx(Gp o0, Mem o1);
	Error movzx(Gp o0, Gp o1);
	Error db(uint8_t o0, size_t o1 = 1) { block(); return Assembler::db(o0, o1); }
	Error dw(uint16_t o0, size_t o1 = 1) { block(); return Assembler::dw(o0, o1); }
	Error dd(uint32_t o0, size_t o1 = 1) { block(); return Assembler::dd(o0, o1); }
	Error dq(uint64_t o0, size_t o1 = 1) { block(); return Assembler::dq(o0, o1); }
	Error embed(void* data, size_t dataSize) { block(); return::Assembler::embed(data, dataSize); }
	Error jz(Label o0) { strict(); return Assembler::jz(o0); }
	Error jz(Imm o0) { strict(); return Assembler::jz(o0); }
	Error jnz(Label o0) { strict(); return Assembler::jnz(o0); }
	Error jnz(Imm o0) { strict(); return Assembler::jnz(o0); }
	Error ja(Label o0) { strict(); return Assembler::ja(o0); }
	Error ja(Imm o0) { strict(); return Assembler::ja(o0); }
	Error jb(Label o0) { strict(); return Assembler::jb(o0); }
	Error jb(Imm o0) { strict(); return Assembler::jb(o0); }
	Error jnb(Label o0) { strict(); return Assembler::jnb(o0); }
	Error jnb(Imm o0) { strict(); return Assembler::jnb(o0); }
	Error jbe(Label o0) { strict(); return Assembler::jbe(o0); }
	Error jbe(Imm o0) { strict(); return Assembler::jbe(o0); }
	Error jae(Label o0) { strict(); return Assembler::jae(o0); }
	Error jae(Imm o0) { strict(); return Assembler::jae(o0); }
	Error jg(Label o0) { strict(); return Assembler::jg(o0); }
	Error jg(Imm o0) { strict(); return Assembler::jg(o0); }
	Error jge(Label o0) { strict(); return Assembler::jge(o0); }
	Error jge(Imm o0) { strict(); return Assembler::jge(o0); }
	Error jl(Label o0) { strict(); return Assembler::jl(o0); }
	Error jl(Imm o0) { strict(); return Assembler::jl(o0); }
	Error jle(Label o0) { strict(); return Assembler::jle(o0); }
	Error jle(Imm o0) { strict(); return Assembler::jle(o0); }
	Error ret();
	Error ret(Imm o0);
	Error align(AlignMode o0, uint32_t o1) { HeldLocks++; Error ret = Assembler::align(o0, o1); HeldLocks--; return ret; }
	Error _emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) override;
	ProtectedAssembler(CodeHolder* pHolder = NULL) : Assembler(pHolder) {}
	~ProtectedAssembler() {}
};

#include "vm.hpp"