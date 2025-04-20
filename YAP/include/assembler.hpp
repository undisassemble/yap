/*!
 * @file assembler.hpp
 * @author undisassemble
 * @brief Obfuscating assembler definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 */

#pragma once
#include "util.hpp"
#include "relib/asm.hpp"
using namespace x86;

/*!
 * @brief Data about a link to be resolved after assembly.
 */
struct NeededLink {
	uint64_t offsetToLink = 0; //!< Offset from shellcode base to write to.
	uint64_t offsetOfRIP = 0;  //!< Address of RIP during resolution.
	uint32_t id = 0;           //!< Label ID.
};

/*!
 * @brief Error logged for AsmJit.
 */
class AsmJitErrorHandler : public ErrorHandler {
public:
	void handleError(_In_ Error error, _In_ const char* message, _In_ BaseEmitter* emitter) override;
};

/*!
 * @brief Obfuscating assembler.
 */
class ProtectedAssembler : public Assembler {
private:
	bool bWaitingOnEmit = false;
	BYTE HeldLocks = 0;
	bool bStrict = false;
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
			LOG(Warning, MODULE_PACKER, "Size mismatch!\n");
		}
		return o1;
	}
	Gp randreg() { return stack.Size() ? stack[rand() % stack.Size()] : (Gp)rsp; }
	Vector<Gp> stack;
	Vector<NeededLink> NeededLinks;
	int randstack(_In_ int nMin = 0, _In_ int nMax = 15);
	void restorestack(_In_ int n = -1);
	void randinst(Gp o0);
	uint64_t GetStackSize();

public:
	/*!
	 * @brief Allow mutation.
	 */
	bool bMutate = true;

	/*!
	 * @brief Allow substitution of instructions.
	 */
	bool bSubstitute = true;

	/*!
	 * @brief Set to true if any instruction failed.
	 */
	bool bFailed = false;

	/*!
	 * @brief How much the generated code should be mutated.
	 */
	BYTE MutationLevel = 3;

	/*!
	 * @brief Resolves unsolved links created by `resolve(Mem o0)`.
	 */
	void resolvelinks();

	/*!
	 * @brief Converts and assembles a decoded instruction.
	 * 
	 * @param [in] pLine Pointer to decoded line.
	 * @param [in] pLabel Pointer to label referenced, if used.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool FromDis(_In_ Line* pLine, _In_ Label* pLabel = NULL);

	/*!
	 * @brief Generate stub in between instructions.
	 */
	void stub();

	/*!
	 * @brief Generate garbage assembly stub, clobbers most registers.
	 * 
	 * @return Size of stub, in bytes.
	 */
	size_t garbage();

	/*!
	 * @brief Causes disassembly desynchronization by combining `jmp -1` and `inc eax`.
	 */
	void desync();

	/*!
	 * @brief Causes disassembly desynchronization by combining `jz -1` and `inc eax`.
	 */
	void desync_jz();

	/*!
	 * @brief Causes disassembly desynchronization by combining `jnz -1` and `inc eax`.
	 */
	void desync_jnz();

	/*!
	 * @brief Causes disassembly desynchronization by popping to rip.
	 * 
	 * @param [in] o0 Register to clobber.
	 */
	void desync_mov(Gpq o0);

	/*!
	 * @brief Prevents `stub()` from running.
	 */
	void block() { bWaitingOnEmit = true; }

	/*!
	 * @brief Prevents `stub()` from modifying `RFLAGS`.
	 */
	void strict() { bStrict = true; }

	/*!
	 * @brief Resolve memory and push to top of stack.
	 * @todo Make this work with labels and with RIP.
	 * 
	 * @param [in] o0 Memory operand to resolve.
	 * @retval true Success.
	 * @retval false Failure, treat as if resolve wasn't used.
	 */
	bool resolve(Mem o0);

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
	Error lea(Gp o0, Mem o1);
	Error db(uint8_t o0, size_t o1 = 1) { block(); return Assembler::db(o0, o1); }
	Error dw(uint16_t o0, size_t o1 = 1) { block(); return Assembler::dw(o0, o1); }
	Error dd(uint32_t o0, size_t o1 = 1) { block(); return Assembler::dd(o0, o1); }
	Error dq(uint64_t o0, size_t o1 = 1) { block(); return Assembler::dq(o0, o1); }
	Error embed(const void* data, size_t dataSize) override { block(); return::Assembler::embed(data, dataSize); }
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
	Error align(AlignMode o0, uint32_t o1) override { HeldLocks++; Error ret = Assembler::align(o0, o1); HeldLocks--; return ret; }
	Error _emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) override;
	ProtectedAssembler(CodeHolder* pHolder = NULL) : Assembler(pHolder) {}
	~ProtectedAssembler() {}
};