#pragma once

#include "asm.hpp"

namespace zyasm {
	ZydisEncoderOperand Op(_In_ ZydisDecodedOperand Op);
	ZydisEncoderOperand Imm(_In_ uint32_t Imm);
	ZydisEncoderOperand Reg(_In_ ZydisRegister Reg);
	ZydisEncoderOperand byte_ptr(_In_ ZydisRegister Base = ZYDIS_REGISTER_NONE, _In_ ZydisRegister Index = ZYDIS_REGISTER_NONE, _In_ BYTE Scale = 0, _In_ int64_t Off = 0);
	ZydisEncoderOperand word_ptr(_In_ ZydisRegister Base = ZYDIS_REGISTER_NONE, _In_ ZydisRegister Index = ZYDIS_REGISTER_NONE, _In_ BYTE Scale = 0, _In_ int64_t Off = 0);
	ZydisEncoderOperand dword_ptr(_In_ ZydisRegister Base = ZYDIS_REGISTER_NONE, _In_ ZydisRegister Index = ZYDIS_REGISTER_NONE, _In_ BYTE Scale = 0, _In_ int64_t Off = 0);
	ZydisEncoderOperand qword_ptr(_In_ ZydisRegister Base = ZYDIS_REGISTER_NONE, _In_ ZydisRegister Index = ZYDIS_REGISTER_NONE, _In_ BYTE Scale = 0, _In_ int64_t Off = 0);
	Vector<Line> push(_In_ ZydisEncoderOperand o0);
	Vector<Line> pop(_In_ ZydisEncoderOperand o0);
	Vector<Line> mov(_In_ ZydisEncoderOperand o0, _In_ ZydisEncoderOperand o1);
	Vector<Line> movzx(_In_ ZydisEncoderOperand o0, _In_ ZydisEncoderOperand o1);
}