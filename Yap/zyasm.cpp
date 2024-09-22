#include "zyasm.hpp"

ZydisRegister _RegOfSize(ZydisRegister Reg, BYTE Size);
BYTE _GetRegSize(ZydisRegister Reg) {
	if (!Reg || Reg > ZYDIS_REGISTER_R15) return 0;
	if (Reg >= ZYDIS_REGISTER_RAX) return 64;
	if (Reg >= ZYDIS_REGISTER_EAX) return 32;
	if (Reg >= ZYDIS_REGISTER_AX) return 16;
	if (Reg >= ZYDIS_REGISTER_AL) return 8;
	return 0;
}
BYTE _GetOpSize(ZydisEncoderOperand o0) {
	switch (o0.type) {
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		return 64;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		return o0.mem.size;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		return _GetRegSize(o0.reg.value);
	}
	return 0;
}

Line _InitLine(ZydisMnemonic Mnemonic, BYTE OpSize) {
	Line ret;
	ret.Type = Request;
	ret.bRelative = false;
	ret.Request.address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_NONE;
	ret.Request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
	ret.Request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
	ret.Request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
	ret.Request.mnemonic = Mnemonic;
	ret.Request.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;
	ZeroMemory(&ret.Request.evex, sizeof(ret.Request.evex));
	ZeroMemory(&ret.Request.mvex, sizeof(ret.Request.mvex));
	ret.Request.prefixes = 0;
	switch (OpSize) {
	case 8:
		ret.Request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_8;
		break;
	case 16:
		ret.Request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_16;
		break;
	case 32:
		ret.Request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_32;
		break;
	case 64:
		ret.Request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_64;
	}
	return ret;
}

ZydisEncoderOperand zyasm::Op(_In_ ZydisDecodedOperand Op) {
	ZydisEncoderOperand ret;
	ret.type = Op.type;
	switch (Op.type) {
	case ZYDIS_OPERAND_TYPE_IMMEDIATE:
		ret.imm.u = Op.imm.value.u;
		break;
	case ZYDIS_OPERAND_TYPE_MEMORY:
		ret.mem.base = Op.mem.base;
		ret.mem.displacement = Op.mem.disp.value;
		ret.mem.index = Op.mem.index;
		ret.mem.scale = Op.mem.scale;
		ret.mem.size = Op.size / 8;
		break;
	case ZYDIS_OPERAND_TYPE_POINTER:
		ret.ptr.offset = Op.ptr.offset;
		ret.ptr.segment = Op.ptr.segment;
		break;
	case ZYDIS_OPERAND_TYPE_REGISTER:
		ret.reg.is4 = ZYAN_FALSE;
		ret.reg.value = Op.reg.value;
	}
	return ret;
}

ZydisEncoderOperand Imm(_In_ uint64_t Imm) {
	ZydisEncoderOperand ret;
	ret.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	ret.imm.u = Imm;
	return ret;
}

ZydisEncoderOperand Reg(_In_ ZydisRegister Reg) {
	ZydisEncoderOperand ret;
	ret.type = ZYDIS_OPERAND_TYPE_REGISTER;
	ret.reg.is4 = ZYAN_FALSE;
	ret.reg.value = Reg;
	return ret;
}

ZydisEncoderOperand zyasm::byte_ptr(_In_ ZydisRegister Base, _In_ ZydisRegister Index, _In_ BYTE Scale, _In_ int64_t Off) {
	ZydisEncoderOperand ret;
	ret.type = ZYDIS_OPERAND_TYPE_MEMORY;
	ret.mem.size = sizeof(BYTE);
	ret.mem.base = Base;
	ret.mem.index = Index;
	ret.mem.scale = Scale;
	ret.mem.displacement = Off;
	return ret;
}

ZydisEncoderOperand zyasm::word_ptr(_In_ ZydisRegister Base, _In_ ZydisRegister Index, _In_ BYTE Scale, _In_ int64_t Off) {
	ZydisEncoderOperand ret = zyasm::byte_ptr(Base, Index, Scale, Off);
	ret.mem.size = sizeof(WORD);
	return ret;
}

ZydisEncoderOperand zyasm::dword_ptr(_In_ ZydisRegister Base, _In_ ZydisRegister Index, _In_ BYTE Scale, _In_ int64_t Off) {
	ZydisEncoderOperand ret = zyasm::byte_ptr(Base, Index, Scale, Off);
	ret.mem.size = sizeof(DWORD);
	return ret;
}

ZydisEncoderOperand zyasm::qword_ptr(_In_ ZydisRegister Base, _In_ ZydisRegister Index, _In_ BYTE Scale, _In_ int64_t Off) {
	ZydisEncoderOperand ret = zyasm::byte_ptr(Base, Index, Scale, Off);
	ret.mem.size = sizeof(QWORD);
	return ret;
}

Vector<Line> zyasm::push(_In_ ZydisEncoderOperand o0) {
	Vector<Line> ret;
	if (_GetOpSize(o0) == 8 || _GetOpSize(o0) == 32 || (o0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o0.imm.u > 0x7FFFFFFF)) return ret;
	Line _inst = _InitLine(ZYDIS_MNEMONIC_PUSH, _GetOpSize(o0));
	_inst.Request.operand_count = 1;
	_inst.Request.operands[0] = o0;
	ret.Push(_inst);
	return ret;
}

Vector<Line> zyasm::pop(_In_ ZydisEncoderOperand o0) {
	Vector<Line> ret;
	if (_GetOpSize(o0) == 8 || _GetOpSize(o0) == 32) LOG(Failed, MODULE_REASSEMBLER, "Attempted to pop byte\n");

	// rsp-relative o0
	if (o0.type == ZYDIS_OPERAND_TYPE_MEMORY && o0.mem.base == ZYDIS_REGISTER_RSP) {
		o0.mem.displacement -= _GetOpSize(o0) / 8;
	}

	Line line = _InitLine(ZYDIS_MNEMONIC_POP, _GetOpSize(o0));
	line.Request.operand_count = 1;
	line.Request.operands[0] = o0;	
	ret.Push(line);
	return ret;
}

Vector<Line> zyasm::mov(_In_ ZydisEncoderOperand o0, _In_ ZydisEncoderOperand o1) {
	Vector<Line> ret;
	if (_GetOpSize(o0) != _GetOpSize(o1) || _GetOpSize(o0) == 32 || _GetOpSize(o0) == 8) return ret;
	ret.Merge(zyasm::push(o1));
	ret.Merge(zyasm::pop(o0));
	if (ret.Size() < 2) ret.Release();
	return ret;
}

Vector<Line> zyasm::movzx(_In_ ZydisEncoderOperand o0, _In_ ZydisEncoderOperand o1) {
	Vector<Line> ret;
	return ret;
}

ZydisRegister _RegOfSize(ZydisRegister Reg, BYTE Size) {
	BYTE RegBase = 0;
	switch (Size) {
	case 32:
		Size = 24;
		break;
	case 64:
		Size = 32;
	}

	// Guh
	switch (Reg) {
	case ZYDIS_REGISTER_AL:
	case ZYDIS_REGISTER_AH:
	case ZYDIS_REGISTER_AX:
	case ZYDIS_REGISTER_EAX:
	case ZYDIS_REGISTER_RAX:
		RegBase = 5;
		break;
	case ZYDIS_REGISTER_CL:
	case ZYDIS_REGISTER_CH:
	case ZYDIS_REGISTER_CX:
	case ZYDIS_REGISTER_ECX:
	case ZYDIS_REGISTER_RCX:
		RegBase = 6;
		break;
	case ZYDIS_REGISTER_DL:
	case ZYDIS_REGISTER_DH:
	case ZYDIS_REGISTER_DX:
	case ZYDIS_REGISTER_EDX:
	case ZYDIS_REGISTER_RDX:
		RegBase = 7;
		break;
	case ZYDIS_REGISTER_BL:
	case ZYDIS_REGISTER_BH:
	case ZYDIS_REGISTER_BX:
	case ZYDIS_REGISTER_EBX:
	case ZYDIS_REGISTER_RBX:
		RegBase = 8;
		break;
	case ZYDIS_REGISTER_SPL:
	case ZYDIS_REGISTER_SP:
	case ZYDIS_REGISTER_ESP:
	case ZYDIS_REGISTER_RSP:
		RegBase = 9;
		break;
	case ZYDIS_REGISTER_BPL:
	case ZYDIS_REGISTER_BP:
	case ZYDIS_REGISTER_EBP:
	case ZYDIS_REGISTER_RBP:
		RegBase = 10;
		break;
	case ZYDIS_REGISTER_SIL:
	case ZYDIS_REGISTER_SI:
	case ZYDIS_REGISTER_ESI:
	case ZYDIS_REGISTER_RSI:
		RegBase = 11;
		break;
	case ZYDIS_REGISTER_DIL:
	case ZYDIS_REGISTER_DI:
	case ZYDIS_REGISTER_EDI:
	case ZYDIS_REGISTER_RDI:
		RegBase = 12;
		break;
	case ZYDIS_REGISTER_R8B:
	case ZYDIS_REGISTER_R8W:
	case ZYDIS_REGISTER_R8D:
	case ZYDIS_REGISTER_R8:
		RegBase = 13;
		break;
	case ZYDIS_REGISTER_R9B:
	case ZYDIS_REGISTER_R9W:
	case ZYDIS_REGISTER_R9D:
	case ZYDIS_REGISTER_R9:
		RegBase = 14;
		break;
	case ZYDIS_REGISTER_R10B:
	case ZYDIS_REGISTER_R10W:
	case ZYDIS_REGISTER_R10D:
	case ZYDIS_REGISTER_R10:
		RegBase = 15;
		break;
	case ZYDIS_REGISTER_R11B:
	case ZYDIS_REGISTER_R11W:
	case ZYDIS_REGISTER_R11D:
	case ZYDIS_REGISTER_R11:
		RegBase = 16;
		break;
	case ZYDIS_REGISTER_R12B:
	case ZYDIS_REGISTER_R12W:
	case ZYDIS_REGISTER_R12D:
	case ZYDIS_REGISTER_R12:
		RegBase = 17;
		break;
	case ZYDIS_REGISTER_R13B:
	case ZYDIS_REGISTER_R13W:
	case ZYDIS_REGISTER_R13D:
	case ZYDIS_REGISTER_R13:
		RegBase = 18;
		break;
	case ZYDIS_REGISTER_R14B:
	case ZYDIS_REGISTER_R14W:
	case ZYDIS_REGISTER_R14D:
	case ZYDIS_REGISTER_R14:
		RegBase = 19;
		break;
	case ZYDIS_REGISTER_R15B:
	case ZYDIS_REGISTER_R15W:
	case ZYDIS_REGISTER_R15D:
	case ZYDIS_REGISTER_R15:
		RegBase = 20;
	}

	Reg = (ZydisRegister)(RegBase + (Size / 8 - 1) * 16);

	// Fix for upper WORD regs
	switch (Reg) {
	case ZYDIS_REGISTER_AH:
		return ZYDIS_REGISTER_AL;
	case ZYDIS_REGISTER_CH:
		return ZYDIS_REGISTER_CL;
	case ZYDIS_REGISTER_DH:
		return ZYDIS_REGISTER_DL;
	case ZYDIS_REGISTER_BH:
		return ZYDIS_REGISTER_BL;
	}
	return Reg;
}