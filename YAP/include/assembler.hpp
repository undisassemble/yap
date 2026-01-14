/*!
 * @file assembler.hpp
 * @author undisassemble
 * @brief Obfuscating assembler definitions
 * @version 0.0.0
 * @date 2026-01-14
 * @copyright MIT License
 */

#pragma once
#include "util.hpp"
#include "relib/asm.hpp"
using namespace x86;

extern Gp _regs[15];

/*!
 * @brief Returns a random 64-bit general-purpose register, other than `rsp`.
 */
Gp truerandreg();

/*!
 * @brief Returns the same general-purpose register, but as a random size. i.e. `randsize(rax)` -> `ax`.
 * 
 * @param [in] o0 Register to change the size of.
 */
Gp randsize(_In_ Gp o0);

/*!
 * @brief Returns a random 64-bit general-purpose register with the same size as `o0`, other than `rsp`. Will not return the same register provided.
 * 
 * @param [in] o0 The register to base the size off of.
 */
Gp randregofsamesize(_In_ Gp o0);

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
	Vector<Gpq> Blacklist;
	Vector<Gp> stack;
	Vector<NeededLink> NeededLinks;

public:
	/*!
	 * @brief Returns a register that can be clobbered safely. Returns `rsp` if no register available (please don't clobber `rsp`).
	 */
	Gp randreg();

	/*!
	 * @brief Saves between `nMin` and `nMax` random registers to the stack.
	 * 
	 * @param [in] nMin Minimum number of registers to save.
	 * @param [in] nMax Maximum number of registers to save.
	 * @return int Number of registers saved.
	 */
	int randstack(_In_ int nMin = 0, _In_ int nMax = 15);

	/*!
	 * @brief Restores `n` registers from the stack.
	 * 
	 * @param [in] n Number of registers to restore, -1 restores them all.
	 */
	void restorestack(_In_ int n = -1);
	
	/*!
	 * @brief Adds a random instruction using `o0`.
	 * 
	 * @param [in] o0 Register to use in whatever instruction it chooses via magic 8 ball.
	 */
	void randinst(_In_ Gp o0);

	/*!
	 * @brief Returns the size (in bytes) of the temporary stack. `rsp + GetStackSize()` = where the original rsp is.
	 */
	uint64_t GetStackSize();

	/*!
	 * @brief Allow mutation.
	 */
	bool bMutate = true;

	/*!
	 * @brief Allow substitution of instructions.
	 */
	bool bSubstitute = true;

	/*!
	 * @brief Allows resolve to handle unbound labels, requires that you call resolvelinks after.
	 */
	bool bAdvancedResolve = true;

	/*!
	 * @brief Set to true if any instruction failed.
	 */
	bool bFailed = false;

	/*!
	 * @brief Force strict mode until manually disabled
	 */
	bool bForceStrict = false;

	/*!
	 * @brief How much the generated code should be mutated.
	 */
	BYTE MutationLevel = 3;

	/*!
	 * @brief Resolves unsolved links created by `resolve(Mem o0)`.
	 */
	void resolvelinks();

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
	 * @brief If the next instruction will avoid modifying `RFLAGS`.
	 */
	bool is_strict() { return bStrict || bForceStrict; }

	/*!
	 * @brief Resolves memory address and pushes to top of stack.
	 * @note Doesn't actually dereference anything, just returns the address.
	 * @todo Make this work with labels and with RIP.
	 * 
	 * @param [in] o0 Memory operand to resolve.
	 * @retval true Success.
	 * @retval false Failure, treat as if resolve wasn't used.
	 */
	bool resolve(_In_ Mem o0);

	Error db(uint8_t o0, size_t o1 = 1) { block(); return Assembler::db(o0, o1); }
	Error dw(uint16_t o0, size_t o1 = 1) { block(); return Assembler::dw(o0, o1); }
	Error dd(uint32_t o0, size_t o1 = 1) { block(); return Assembler::dd(o0, o1); }
	Error dq(uint64_t o0, size_t o1 = 1) { block(); return Assembler::dq(o0, o1); }
	Error embed(const void* data, size_t dataSize) override { block(); return Assembler::embed(data, dataSize); }
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
	Error align(AlignMode o0, uint32_t o1) override { HeldLocks++; Error ret = Assembler::align(o0, o1); HeldLocks--; return ret; }
	Error _emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) override;
	ProtectedAssembler(CodeHolder* pHolder = NULL) : Assembler(pHolder) {}
	~ProtectedAssembler() {}
};