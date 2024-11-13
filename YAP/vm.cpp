#include "vm.hpp"

BYTE RandomizedOpcodes[47] = { 0 };
BYTE RandomizedRegisters[77] = { 0 };
BYTE RandomizedSizes[4] = { 0 };
BYTE RandomizedOperands[4] = { 0 };

Label GenerateVMParser(_In_ PE* pPackedBinary, _In_ PE* pOriginal, _In_ PackerOptions Options, _In_ _ShellcodeData ShellcodeData, _In_ Assembler* pA, _In_ Label FunctionPtrs) {
	Label VMParser = pA->newLabel();

	// Register purpose:
	// rax - current function base
	// rbx - simulated RIP
	// rcx - current instruction pointer
	// rdx - current operand pointer
	// r8  - return register
	// r9-r15 - working registers

	// Virtual registers
	Label v_rax = pA->newLabel();
	pA->bind(v_rax);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_rbx = pA->newLabel();
	pA->bind(v_rbx);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_rcx = pA->newLabel();
	pA->bind(v_rcx);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_rdx = pA->newLabel();
	pA->bind(v_rdx);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_rsi = pA->newLabel();
	pA->bind(v_rsi);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r8 = pA->newLabel();
	pA->bind(v_r8);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r9 = pA->newLabel();
	pA->bind(v_r9);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r10 = pA->newLabel();
	pA->bind(v_r10);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r11 = pA->newLabel();
	pA->bind(v_r11);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r12 = pA->newLabel();
	pA->bind(v_r12);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r13 = pA->newLabel();
	pA->bind(v_r13);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r14 = pA->newLabel();
	pA->bind(v_r14);
	pA->dq((uint64_t)rand() << 32 | rand());
	Label v_r15 = pA->newLabel();
	pA->bind(v_r15);
	pA->dq((uint64_t)rand() << 32 | rand());
	
	// Save registers
	pA->bind(VMParser);
	pA->mov(ptr(v_rax), rax);
	pA->mov(ptr(v_rbx), rbx);
	pA->mov(ptr(v_rcx), rcx);
	pA->mov(ptr(v_rdx), rdx);
	pA->mov(ptr(v_rsi), rsi);
	pA->mov(ptr(v_r8), r8);
	pA->mov(ptr(v_r9), r9);
	pA->mov(ptr(v_r10), r10);
	pA->mov(ptr(v_r11), r11);
	pA->mov(ptr(v_r12), r12);
	pA->mov(ptr(v_r13), r13);
	pA->mov(ptr(v_r14), r14);
	pA->mov(ptr(v_r15), r15);


	// Restore registers and return to non-virtualized area
	pA->mov(rax, ptr(v_rax));
	pA->mov(rbx, ptr(v_rbx));
	pA->mov(rcx, ptr(v_rcx));
	pA->mov(rdx, ptr(v_rdx));
	pA->mov(rsi, ptr(v_rsi));
	pA->mov(r8, ptr(v_r8));
	pA->mov(r9, ptr(v_r9));
	pA->mov(r10, ptr(v_r10));
	pA->mov(r11, ptr(v_r11));
	pA->mov(r12, ptr(v_r12));
	pA->mov(r13, ptr(v_r13));
	pA->mov(r14, ptr(v_r14));
	pA->mov(r15, ptr(v_r15));
	pA->ret();

	return VMParser;
}