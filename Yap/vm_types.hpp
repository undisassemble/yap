#pragma once

enum VirtualizedMnemonic : BYTE {
	// CF-changing instructions
	CALL,
	LOOP,
	LOOPE,
	LOOPNE,
	JB,
	JBE,
	JCXZ,
	JECXZ,
	JKNZD,
	JKZD,
	JL,
	JLE,
	JMP,
	JNB,
	JNBE,
	JNL,
	JNLE,
	JNO,
	JNP,
	JNS,
	JNZ,
	JO,
	JP,
	JRCXZ,
	JS,
	JZ,

	// Register modifying instructions
	MOV,
	MOVZX,
	MOVSXD,
	LEA,
	SHR,
	SHL,
	XOR,
	AND,
	OR,
	NOT,
	ADD,
	SUB,
	INC,
	DEC,
	IMUL,
	IDIV,

	// Misc
	PUSH,
	POP,
	TEST,
	CMP,

	// For raw instructions
	RAW,
};

enum VirtualizedOperandType : BYTE {
	None,
	Imm,
	Mem,
	Reg,
};

enum VirtualizedRegister : BYTE {
	UNKNOWN,
	NO_REG,

	// Segments
	CS,
	SS,
	DS,
	ES,
	FS,
	GS,

	RIP,

	// 64-bit
	RAX,
	RBX,
	RCX,
	RDX,
	RDI,
	RSI,
	RBP,
	RSP,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,

	// 32-bit
	EAX,
	EBX,
	ECX,
	EDX,
	EDI,
	ESI,
	EBP,
	ESP,
	R8D,
	R9D,
	R10D,
	R11D,
	R12D,
	R13D,
	R14D,
	R15D,

	// 16-bit
	AX,
	BX,
	CX,
	DX,
	DI,
	SI,
	BP,
	SP,
	R8W,
	R9W,
	R10W,
	R11W,
	R12W,
	R13W,
	R14W,
	R15W,

	// 8-bit
	AL,
	BL,
	CL,
	DL,
	DIL,
	SIL,
	BPL,
	SPL,
	R8B,
	R9B,
	R10B,
	R11B,
	R12B,
	R13B,
	R14B,
	R15B,

	// 8-bit upper
	AH,
	BH,
	CH,
	DH,
};

enum VirtualizedSize : BYTE {
	BIT_8,
	BIT_16,
	BIT_32,
	BIT_64,
};

const BYTE SizeMem = 12;
const BYTE SizeImm = 9;
const BYTE SizeReg = sizeof(VirtualizedRegister) + 1;
const BYTE SizeRaw = 16;
const BYTE BaseSize = 6;

struct VirtualizedOperand {
	VirtualizedOperandType Type : 2;
	union {
		struct {
			VirtualizedSize Size : 2;
			uint64_t Value;
		} Imm;
		struct {
			VirtualizedSize Size : 2;
			VirtualizedRegister Segment : 3;
			BYTE Shift : 2;
			VirtualizedRegister Base;
			VirtualizedRegister Index;
			uint64_t Offset;
		} Mem;
		VirtualizedRegister Register;
	};
};

struct EncodedInstruction {
	uint32_t OldRIP = 0;
	uint32_t OldRVA = 0;
	VirtualizedMnemonic Mnemonic = RAW;
	BYTE NumOperands : 2 = 0;
	BYTE InstructionSize : 6 = 0;
};

struct EncodedRaw {
	BYTE Instruction[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
	VirtualizedRegister SimulatedRIP = UNKNOWN; // unknown if instruction never references RIP
};

struct VirtualizedInstruction {
	DWORD OldRVA = 0;
	VirtualizedMnemonic Mnemonic = RAW;
	BYTE NumOperands = 0;
	BYTE Size = 0;
	union {
		VirtualizedOperand Operands[3] = { 0 };
		EncodedRaw RawInstruction;
	};
};

VirtualizedSize BitCountToVirtualizedSize(BYTE Bits) {
	switch (Bits) {
	case 16:
		return BIT_16;
	case 32:
		return BIT_32;
	case 64:
		return BIT_64;
	}
	return BIT_8;
}

VirtualizedRegister ZydisRegisterToVirtualizedRegister(ZydisRegister Register) {
	switch (Register) {
	case ZYDIS_REGISTER_CS:
		return CS;
	case ZYDIS_REGISTER_SS:
		return SS;
	case ZYDIS_REGISTER_DS:
		return DS;
	case ZYDIS_REGISTER_ES:
		return ES;
	case ZYDIS_REGISTER_FS:
		return FS;
	case ZYDIS_REGISTER_GS:
		return GS;
	case ZYDIS_REGISTER_RAX:
		return RAX;
	case ZYDIS_REGISTER_RBX:
		return RBX;
	case ZYDIS_REGISTER_RCX:
		return RCX;
	case ZYDIS_REGISTER_RDX:
		return RDX;
	case ZYDIS_REGISTER_RDI:
		return RDI;
	case ZYDIS_REGISTER_RSI:
		return RSI;
	case ZYDIS_REGISTER_RBP:
		return RBP;
	case ZYDIS_REGISTER_RSP:
		return RSP;
	case ZYDIS_REGISTER_R8:
		return R8;
	case ZYDIS_REGISTER_R9:
		return R9;
	case ZYDIS_REGISTER_R10:
		return R10;
	case ZYDIS_REGISTER_R11:
		return R11;
	case ZYDIS_REGISTER_R12:
		return R12;
	case ZYDIS_REGISTER_R13:
		return R13;
	case ZYDIS_REGISTER_R14:
		return R14;
	case ZYDIS_REGISTER_R15:
		return R15;
	case ZYDIS_REGISTER_EAX:
		return EAX;
	case ZYDIS_REGISTER_EBX:
		return EBX;
	case ZYDIS_REGISTER_ECX:
		return ECX;
	case ZYDIS_REGISTER_EDX:
		return EDX;
	case ZYDIS_REGISTER_EDI:
		return EDI;
	case ZYDIS_REGISTER_ESI:
		return ESI;
	case ZYDIS_REGISTER_EBP:
		return EBP;
	case ZYDIS_REGISTER_ESP:
		return ESP;
	case ZYDIS_REGISTER_R8D:
		return R8D;
	case ZYDIS_REGISTER_R9D:
		return R9D;
	case ZYDIS_REGISTER_R10D:
		return R10D;
	case ZYDIS_REGISTER_R11D:
		return R11D;
	case ZYDIS_REGISTER_R12D:
		return R12D;
	case ZYDIS_REGISTER_R13D:
		return R13D;
	case ZYDIS_REGISTER_R14D:
		return R14D;
	case ZYDIS_REGISTER_R15D:
		return R15D;
	case ZYDIS_REGISTER_AX:
		return AX;
	case ZYDIS_REGISTER_BX:
		return BX;
	case ZYDIS_REGISTER_CX:
		return CX;
	case ZYDIS_REGISTER_DX:
		return DX;
	case ZYDIS_REGISTER_DI:
		return DI;
	case ZYDIS_REGISTER_SI:
		return SI;
	case ZYDIS_REGISTER_BP:
		return BP;
	case ZYDIS_REGISTER_SP:
		return SP;
	case ZYDIS_REGISTER_R8W:
		return R8W;
	case ZYDIS_REGISTER_R9W:
		return R9W;
	case ZYDIS_REGISTER_R10W:
		return R10W;
	case ZYDIS_REGISTER_R11W:
		return R11W;
	case ZYDIS_REGISTER_R12W:
		return R12W;
	case ZYDIS_REGISTER_R13W:
		return R13W;
	case ZYDIS_REGISTER_R14W:
		return R14W;
	case ZYDIS_REGISTER_R15W:
		return R15W;
	case ZYDIS_REGISTER_AL:
		return AL;
	case ZYDIS_REGISTER_BL:
		return BL;
	case ZYDIS_REGISTER_CL:
		return CL;
	case ZYDIS_REGISTER_DL:
		return DL;
	case ZYDIS_REGISTER_DIL:
		return DIL;
	case ZYDIS_REGISTER_SIL:
		return SIL;
	case ZYDIS_REGISTER_BPL:
		return BPL;
	case ZYDIS_REGISTER_SPL:
		return SPL;
	case ZYDIS_REGISTER_R8B:
		return R8B;
	case ZYDIS_REGISTER_R9B:
		return R9B;
	case ZYDIS_REGISTER_R10B:
		return R10B;
	case ZYDIS_REGISTER_R11B:
		return R11B;
	case ZYDIS_REGISTER_R12B:
		return R12B;
	case ZYDIS_REGISTER_R13B:
		return R13B;
	case ZYDIS_REGISTER_R14B:
		return R14B;
	case ZYDIS_REGISTER_R15B:
		return R15B;
	case ZYDIS_REGISTER_AH:
		return AH;
	case ZYDIS_REGISTER_BH:
		return BH;
	case ZYDIS_REGISTER_CH:
		return CH;
	case ZYDIS_REGISTER_DH:
		return DH;
	case ZYDIS_REGISTER_NONE:
		return NO_REG;
	}
	return UNKNOWN;
}

VirtualizedMnemonic ZydisMnemonicToVirtualizedMnemonic(ZydisMnemonic Mnemonic) {
	switch (Mnemonic) {
	case ZYDIS_MNEMONIC_CALL:
		return CALL;
	case ZYDIS_MNEMONIC_LOOP:
		return LOOP;
	case ZYDIS_MNEMONIC_LOOPE:
		return LOOPE;
	case ZYDIS_MNEMONIC_LOOPNE:
		return LOOPNE;
	case ZYDIS_MNEMONIC_JB:
		return JB;
	case ZYDIS_MNEMONIC_JBE:
		return JBE;
	case ZYDIS_MNEMONIC_JCXZ:
		return JCXZ;
	case ZYDIS_MNEMONIC_JECXZ:
		return JECXZ;
	case ZYDIS_MNEMONIC_JKNZD:
		return JKNZD;
	case ZYDIS_MNEMONIC_JKZD:
		return JKZD;
	case ZYDIS_MNEMONIC_JL:
		return JL;
	case ZYDIS_MNEMONIC_JLE:
		return JLE;
	case ZYDIS_MNEMONIC_JMP:
		return JMP;
	case ZYDIS_MNEMONIC_JNB:
		return JNB;
	case ZYDIS_MNEMONIC_JNBE:
		return JNBE;
	case ZYDIS_MNEMONIC_JNL:
		return JNL;
	case ZYDIS_MNEMONIC_JNLE:
		return JNLE;
	case ZYDIS_MNEMONIC_JNO:
		return JNO;
	case ZYDIS_MNEMONIC_JNP:
		return JNP;
	case ZYDIS_MNEMONIC_JNS:
		return JNS;
	case ZYDIS_MNEMONIC_JNZ:
		return JNZ;
	case ZYDIS_MNEMONIC_JO:
		return JO;
	case ZYDIS_MNEMONIC_JP:
		return JP;
	case ZYDIS_MNEMONIC_JRCXZ:
		return JRCXZ;
	case ZYDIS_MNEMONIC_JS:
		return JS;
	case ZYDIS_MNEMONIC_JZ:
		return JZ;
	case ZYDIS_MNEMONIC_MOV:
		return MOV;
	case ZYDIS_MNEMONIC_MOVZX:
		return MOVZX;
	case ZYDIS_MNEMONIC_MOVSXD:
		return MOVSXD;
	case ZYDIS_MNEMONIC_LEA:
		return LEA;
	case ZYDIS_MNEMONIC_SHR:
		return SHR;
	case ZYDIS_MNEMONIC_SHL:
		return SHL;
	case ZYDIS_MNEMONIC_XOR:
		return XOR;
	case ZYDIS_MNEMONIC_AND:
		return AND;
	case ZYDIS_MNEMONIC_OR:
		return OR;
	case ZYDIS_MNEMONIC_NOT:
		return NOT;
	case ZYDIS_MNEMONIC_ADD:
		return ADD;
	case ZYDIS_MNEMONIC_SUB:
		return SUB;
	case ZYDIS_MNEMONIC_INC:
		return INC;
	case ZYDIS_MNEMONIC_DEC:
		return DEC;
	case ZYDIS_MNEMONIC_IMUL:
		return IMUL;
	case ZYDIS_MNEMONIC_IDIV:
		return IDIV;
	case ZYDIS_MNEMONIC_PUSH:
		return PUSH;
	case ZYDIS_MNEMONIC_POP:
		return POP;
	case ZYDIS_MNEMONIC_TEST:
		return TEST;
	case ZYDIS_MNEMONIC_CMP:
		return CMP;
	}
	return RAW;
}