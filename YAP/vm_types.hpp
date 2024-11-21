#pragma once

enum VirtMnem_t : BYTE {
	VM_NOP,
	
	// CF
	VM_CALL,
	VM_LOOP,
	VM_LOOPE,
	VM_LOOPNE,
	VM_JMP,
	VM_JA,
	VM_JAE,
	VM_JB,
	VM_JBE,
	VM_JC,
	VM_JCXZ,
	VM_JECXZ,
	VM_JRCXZ,
	VM_JE,
	VM_JG,
	VM_JGE,
	VM_JL,
	VM_JLE,
	VM_JNA,
	VM_JNAE,
	VM_JNB,
	VM_JNBE,
	VM_JNC,
	VM_JNE,
	VM_JNG,
	VM_JNGE,
	VM_JNL,
	VM_JNLE,
	VM_JNO,
	VM_JNP,
	VM_JNS,
	VM_JNZ,
	VM_JO,
	VM_JP,
	VM_JPE,
	VM_JPO,
	VM_JS,
	VM_JZ,
	
	// Other common ones
	VM_PUSH,
	VM_POP,
	VM_ADD,
	VM_SUB,
	VM_XOR,
	VM_OR,
	VM_AND,
	VM_MOV,
	VM_MOVZX,
	VM_LEA,
	VM_CMP,
	VM_TEST,
	VM_CDQE,
	VM_SETA,
	VM_SETAE,
	VM_SETB,
	VM_SETBE,
	VM_SETC,
	VM_SETE,
	VM_SETG,
	VM_SETGE,
	VM_SETL,
	VM_SETLE,
	VM_SETNA,
	VM_SETNAE,
	VM_SETNB,
	VM_SETNBE,
	VM_SETNC,
	VM_SETNE,
	VM_SETNG,
	VM_SETNGE,
	VM_SETNL,
	VM_SETNLE,
	VM_SETNO,
	VM_SETNP,
	VM_SETNS,
	VM_SETNZ,
	VM_SETO,
	VM_SETP,
	VM_SETPE,
	VM_SETPO,
	VM_SETS,
	VM_SETZ,

	// Special
	VM_RAW,
	VM_GET_PEB,
	VM_GET_TEB,
	VM_END
};

enum VirtOpMode_t : BYTE {
	VM_OP_NONE,
	VM_OP_MEM,
	VM_OP_REG,
	VM_OP_IMM
};

enum VirtReg_t : BYTE {
	VM_REG_NONE,
	
	// 64-bit
	VM_REG_RAX,
	VM_REG_RBX,
	VM_REG_RCX,
	VM_REG_RDX,
	VM_REG_RSI,
	VM_REG_RDI,
	VM_REG_RBP,
	VM_REG_RSP,
	VM_REG_R8,
	VM_REG_R9,
	VM_REG_R10,
	VM_REG_R11,
	VM_REG_R12,
	VM_REG_R13,
	VM_REG_R14,
	VM_REG_R15,

	// 32-bit
	VM_REG_EAX,
	VM_REG_EBX,
	VM_REG_ECX,
	VM_REG_EDX,
	VM_REG_ESI,
	VM_REG_EDI,
	VM_REG_EBP,
	VM_REG_ESP,
	VM_REG_R8D,
	VM_REG_R9D,
	VM_REG_R10D,
	VM_REG_R11D,
	VM_REG_R12D,
	VM_REG_R13D,
	VM_REG_R14D,
	VM_REG_R15D,

	// 16-bit
	VM_REG_AX,
	VM_REG_BX,
	VM_REG_CX,
	VM_REG_DX,
	VM_REG_SI,
	VM_REG_DI,
	VM_REG_BP,
	VM_REG_SP,
	VM_REG_R8W,
	VM_REG_R9W,
	VM_REG_R10W,
	VM_REG_R11W,
	VM_REG_R12W,
	VM_REG_R13W,
	VM_REG_R14W,
	VM_REG_R15W,

	// 8-bit
	VM_REG_AL,
	VM_REG_BL,
	VM_REG_CL,
	VM_REG_DL,
	VM_REG_SIL,
	VM_REG_DIL,
	VM_REG_BPL,
	VM_REG_SPL,
	VM_REG_R8B,
	VM_REG_R9B,
	VM_REG_R10B,
	VM_REG_R11B,
	VM_REG_R12B,
	VM_REG_R13B,
	VM_REG_R14B,
	VM_REG_R15B,

	// Special
	VM_REG_AH,
	VM_REG_BH,
	VM_REG_CH,
	VM_REG_DH,
	VM_REG_EIP,
	VM_REG_RIP,
	VM_REG_RFLAGS,
	VM_REG_EFLAGS
};

/// <summary>
/// [Base + Index << Shift + Off] Operand (doesn't support segments)
/// Size should be in bits
/// </summary>
struct VirtMem_t {
	VirtReg_t Base = VM_REG_NONE;
	VirtReg_t Index = VM_REG_NONE;
	BYTE Shift = 0;
	QWORD Off = 0;
	BYTE Size = 0;
};

/// <summary>
/// Operand
/// </summary>
struct VirtOp_t {
	VirtOpMode_t Type = VM_OP_NONE;
	union {
		QWORD Imm;
		VirtReg_t Reg;
		VirtMem_t Mem;
	};
};

/// <summary>
/// Instruction
/// </summary>
struct VirtInst_t {
	VirtMnem_t Mnemonic = VM_NOP;
	union {
		BYTE Raw[15] = { 0 };
		struct {
			BYTE NumOperands;
			VirtOp_t Operands[3];
		};
	};
};