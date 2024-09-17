#include "vm.hpp"
#include "vm_types.hpp"

// Replacement code
BYTE ReplaceCode[] = {
	0x6A, 0x00,                                                              // push id
	0x50,                                                                    // push rax
	0x50,                                                                    // push rax
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,              // mov rax, VMParser
	0x48, 0x89, 0x44, 0x24, 0x08,                                            // mov qword ptr [rsp + 0x08], rax
	0x58,                                                                    // pop rax
	0xC3                                                                     // ret
};
BYTE OffID = 1;
BYTE OffPtr = 6;

BYTE RandomizedOpcodes[47] = { 0 };
BYTE RandomizedRegisters[77] = { 0 };
BYTE RandomizedSizes[4] = { 0 };
BYTE RandomizedOperands[4] = { 0 };

Vector<VirtualizedInstruction> DisassembleRecursive(_In_ PE* pOriginal, _In_ DWORD dwRVA);

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
	
	// Prepare to execute
	pA->pop(rbx); // Get function ID
	pA->lea(rax, ptr(FunctionPtrs));
	pA->mov(ebx, dword_ptr(rax, al, 2, 0));
	pA->sub(rax, rbx);
	pA->mov(rcx, rax);
	Label skipintro = pA->newLabel();
	pA->jmp(skipintro);

	// Execution loop
	Label loop = pA->newLabel();
	pA->bind(loop);
	pA->movzx(r8d, byte_ptr(rcx, 9));
	pA->and_(r8b, 0b00111111);
	pA->add(rcx, r8);
	pA->bind(skipintro);
	pA->mov(ebx, dword_ptr(rcx)); // Load RIP
	for (int i = 0; i < sizeof(RandomizedOpcodes); i++) {
		Label skip = pA->newLabel();
		pA->cmp(byte_ptr(rcx, 8), i);
		pA->jne(skip);

		// fuck it ill do it later
		switch (RandomizedOpcodes[i]) {
		case RAW: {
			
			for (int j = 0; j < ZYDIS_MAX_INSTRUCTION_LENGTH; j++) {
				pA->db(rand() & 255);
			}
			break;
		}
		case CALL: {

			break;
		}
		}

		pA->bind(skip);
	}

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

VirtualizeResult Virtualize(_In_ PE* pOriginal, _In_ PackerOptions Options, _In_ Assembler* pA, _In_ Label FunctionPtrs) {
	// Randomized shit
	for (int i = 0; i < sizeof(RandomizedOpcodes); i++) {
		RandomizedOpcodes[i] = rand() % sizeof(RandomizedOpcodes);
		for (int j = 0; j < i; j++) {
			if (RandomizedOpcodes[i] == RandomizedOpcodes[j]) {
				i--;
				break;
			}
		}
	}
	for (int i = 0; i < sizeof(RandomizedOperands); i++) {
		RandomizedOperands[i] = rand() % sizeof(RandomizedOperands);
		for (int j = 0; j < i; j++) {
			if (RandomizedOperands[i] == RandomizedOperands[j]) {
				i--;
				break;
			}
		}
	}
	for (int i = 0; i < sizeof(RandomizedRegisters); i++) {
		RandomizedRegisters[i] = rand() % sizeof(RandomizedRegisters);
		for (int j = 0; j < i; j++) {
			if (RandomizedRegisters[i] == RandomizedRegisters[j]) {
				i--;
				break;
			}
		}
	}
	for (int i = 0; i < sizeof(RandomizedSizes); i++) {
		RandomizedSizes[i] = rand() % sizeof(RandomizedSizes);
		for (int j = 0; j < i; j++) {
			if (RandomizedSizes[i] == RandomizedSizes[j]) {
				i--;
				break;
			}
		}
	}

	VirtualizeResult ret;
	Vector<DWORD> FunctionOffsets;
	EncodedInstruction CurrentInstruction;

	for (int i = 0, n = Options.VMFuncs.Size(); i < n; i++) {
		// Turn asm into virtual instructions
		Vector<VirtualizedInstruction> Virtualized = DisassembleRecursive(pOriginal, Options.VMFuncs.At(i));

		// Resize/encode each instruction and add
		DWORD dwOff = 0;
		for (int j = 0, m = Virtualized.Size(); j < m; j++) {
			CurrentInstruction.OldRVA = Virtualized.At(j).OldRVA;
			CurrentInstruction.Mnemonic = (VirtualizedMnemonic)RandomizedOperands[Virtualized.At(j).Mnemonic];
			CurrentInstruction.NumOperands = Virtualized.At(j).NumOperands;
			CurrentInstruction.OldRIP = CurrentInstruction.OldRIP + Virtualized.At(j).Size;
			
			// Predict size (yes I know the alphabet goes mno not nmo shut the fuckup)
			if (CurrentInstruction.Mnemonic == (VirtualizedMnemonic)RandomizedOperands[VirtualizedMnemonic::RAW]) {
				CurrentInstruction.InstructionSize = BaseSize + SizeRaw;
				dwOff += BaseSize + SizeRaw;
				pA->embed(&CurrentInstruction, BaseSize);
				pA->embed(&Virtualized.At(j).RawInstruction, SizeRaw);
				continue;
			} else {
				CurrentInstruction.InstructionSize = BaseSize;
				for (int k = 0, o = CurrentInstruction.NumOperands; k < o; k++) {
					switch (Virtualized.At(j).Operands[k].Type) {
					case VirtualizedOperandType::Imm:
						CurrentInstruction.InstructionSize += SizeImm;
						break;
					case VirtualizedOperandType::Mem:
						CurrentInstruction.InstructionSize += SizeMem;
						break;
					case VirtualizedOperandType::Reg:
						CurrentInstruction.InstructionSize += SizeReg;
					default:
						break;
					}
				}
			}

			// Add encoded instruction
			dwOff += BaseSize;
			pA->embed(&CurrentInstruction, BaseSize);

			// Add operands
			for (int k = 0, o = CurrentInstruction.NumOperands; k < o; k++) {
				BYTE size = 0;
				switch (Virtualized.At(j).Operands[k].Type) {
				case VirtualizedOperandType::Imm:
					size = SizeImm;
					break;
				case VirtualizedOperandType::Mem:
					size += SizeMem;
					Virtualized.At(j).Operands[k].Mem.Base = (VirtualizedRegister)RandomizedRegisters[Virtualized.At(j).Operands[k].Mem.Base];
					Virtualized.At(j).Operands[k].Mem.Index = (VirtualizedRegister)RandomizedRegisters[Virtualized.At(j).Operands[k].Mem.Index];
					Virtualized.At(j).Operands[k].Mem.Segment = (VirtualizedRegister)RandomizedRegisters[Virtualized.At(j).Operands[k].Mem.Segment];
					break;
				case VirtualizedOperandType::Reg:
					size += SizeReg;
					Virtualized.At(j).Operands[k].Register = (VirtualizedRegister)RandomizedRegisters[Virtualized.At(j).Operands[k].Register];
				default:
					break;
				}
				dwOff + size;
				Virtualized.At(j).Operands[k].Type = (VirtualizedOperandType)RandomizedOperands[Virtualized.At(j).Operands[k].Type];
				pA->embed(&Virtualized.At(j).Operands[k], size);
			}
		}

		// Change offsets
		for (int j = 0, m = FunctionOffsets.Size(); j < m; j++) {
			FunctionOffsets.Replace(j, FunctionOffsets.At(j) + dwOff);
		}
		FunctionOffsets.Push(dwOff);

		// Write hook
		ReplaceCode[OffID] = i;
		ret.RelocRVAs.Push(Options.VMFuncs.At(i) + OffPtr);
		pOriginal->WriteRVA(Options.VMFuncs.At(i), ReplaceCode, sizeof(ReplaceCode));
	}

	// Embed data
	pA->bind(FunctionPtrs);
	for (int i = 0, n = FunctionOffsets.Size(); i < n; i++) {
		pA->dd(FunctionOffsets.At(i));
	}

	return ret;
}

Vector<VirtualizedInstruction> DisassembleRecursive(_In_ PE* pOriginal, _In_ DWORD dwRVA) {
	// Setup zydis
	Vector<DWORD> ToDisasm;
	Vector<DWORD> Done;
	Vector<VirtualizedInstruction> ret;
	ZydisDecoder Decoder;
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
	VirtualizedInstruction VirtInstruction;
	ZydisEncoderRequest Request;
	BYTE Overwrite[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0xCC };

	do {
		// Get buffer
		Buffer SecBuf = pOriginal->GetSectionBytes(pOriginal->FindSectionByRVA(dwRVA));
		IMAGE_SECTION_HEADER* pHeader = pOriginal->GetSectionHeader(pOriginal->FindSectionByRVA(dwRVA));
		if (!SecBuf.pBytes || !SecBuf.u64Size || !pHeader) return ret;
		SecBuf.pBytes += dwRVA - pHeader->VirtualAddress;
		SecBuf.u64Size -= dwRVA - pHeader->VirtualAddress;

		// Disassemble
		while (SecBuf.u64Size && !Done.Includes(dwRVA) && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, SecBuf.pBytes, SecBuf.u64Size, &Instruction, Operands))) {
			Done.Push(dwRVA);
			VirtInstruction.OldRVA = dwRVA;
			VirtInstruction.Mnemonic = ZydisMnemonicToVirtualizedMnemonic(Instruction.mnemonic);
			VirtInstruction.Size = Instruction.length;

			// Insert instruction operands
			if (VirtInstruction.Mnemonic != RAW) {
				VirtInstruction.NumOperands = Instruction.operand_count_visible;
				for (int i = 0; i < Instruction.operand_count_visible; i++) {
					switch (Operands[i].type) {
					case ZYDIS_OPERAND_TYPE_IMMEDIATE:
						VirtInstruction.Operands[i].Type = VirtualizedOperandType::Imm;
						VirtInstruction.Operands[i].Imm.Value = Operands[i].imm.value.u;
						VirtInstruction.Operands[i].Imm.Size = BitCountToVirtualizedSize(Operands[i].imm.size);
						break;
					case ZYDIS_OPERAND_TYPE_REGISTER:
						VirtInstruction.Operands[i].Type = VirtualizedOperandType::Reg;
						VirtInstruction.Operands[i].Register = ZydisRegisterToVirtualizedRegister(Operands[i].reg.value);
						if (VirtInstruction.Operands[i].Register == UNKNOWN) goto go_raw;
						break;
					case ZYDIS_OPERAND_TYPE_POINTER:
						LOG(Failed, MODULE_VM, "Came accross pointer operand at RVA %du!\n", dwRVA);
						exit(0);
						break;
					case ZYDIS_OPERAND_TYPE_MEMORY:
						VirtInstruction.Operands[i].Type = VirtualizedOperandType::Mem;
						VirtInstruction.Operands[i].Mem.Offset = Operands[i].mem.disp.value;
						VirtInstruction.Operands[i].Mem.Shift = Operands[i].mem.scale;
						VirtInstruction.Operands[i].Mem.Base = ZydisRegisterToVirtualizedRegister(Operands[i].mem.base);
						VirtInstruction.Operands[i].Mem.Index = ZydisRegisterToVirtualizedRegister(Operands[i].mem.index);
						VirtInstruction.Operands[i].Mem.Segment = ZydisRegisterToVirtualizedRegister(Operands[i].mem.segment);
						VirtInstruction.Operands[i].Mem.Size = BitCountToVirtualizedSize(Operands[i].size);
						if (VirtInstruction.Operands[i].Mem.Base == UNKNOWN || VirtInstruction.Operands[i].Mem.Index == UNKNOWN || VirtInstruction.Operands[i].Mem.Segment == UNKNOWN) goto go_raw;
						break;
					}
				}
			} else {
			go_raw:
				VirtInstruction.Mnemonic = RAW;
				// Look for RIP-relative memory
				ZydisRegister SimulatedRIP = ZYDIS_REGISTER_RAX;
				VirtInstruction.RawInstruction.SimulatedRIP = UNKNOWN;
				for (int i = 0; i < Instruction.operand_count; i++) {
					if (
						(Operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER && Operands[i].reg.value == SimulatedRIP) ||
						(Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && (Operands[i].mem.base == SimulatedRIP) || Operands[i].mem.index == SimulatedRIP)
					) {
						SimulatedRIP = (ZydisRegister)(SimulatedRIP + 1);
					}
				}
				for (int i = 0; i < Instruction.operand_count; i++) {
					if (Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && Operands[i].mem.base == ZYDIS_REGISTER_RIP) {
						Operands[i].mem.base = SimulatedRIP;
						VirtInstruction.RawInstruction.SimulatedRIP = ZydisRegisterToVirtualizedRegister(SimulatedRIP);
						break;
					}
				}

				// Prevent RIP-relative memory addressing from being wonky
				if (VirtInstruction.RawInstruction.SimulatedRIP != UNKNOWN) {
					ZydisEncoderDecodedInstructionToEncoderRequest(&Instruction, Operands, Instruction.operand_count_visible, &Request);
					ZyanUSize TempSize = ZYDIS_MAX_INSTRUCTION_LENGTH;
					ZydisEncoderEncodeInstruction(&Request, VirtInstruction.RawInstruction.Instruction, &TempSize);
					memset(&VirtInstruction.RawInstruction.Instruction[TempSize], 0x90, ZYDIS_MAX_INSTRUCTION_LENGTH - TempSize);
				} else {
					memset(VirtInstruction.RawInstruction.Instruction, 0x90, ZYDIS_MAX_INSTRUCTION_LENGTH);
					memcpy(VirtInstruction.RawInstruction.Instruction, SecBuf.pBytes, Instruction.length);
				}
			}

			// Overwrite
			pOriginal->WriteRVA(dwRVA, Overwrite, Instruction.length);

			// Prepare for next instruction
			SecBuf.pBytes += Instruction.length;
			SecBuf.u64Size -= Instruction.length;
			dwRVA += Instruction.length;
		}

		// Handle CF stuff
		uint64_t Address = 0;
		switch (Instruction.mnemonic) {
		case ZYDIS_MNEMONIC_LOOP:
		case ZYDIS_MNEMONIC_LOOPE:
		case ZYDIS_MNEMONIC_LOOPNE:
		case ZYDIS_MNEMONIC_JB:
		case ZYDIS_MNEMONIC_JBE:
		case ZYDIS_MNEMONIC_JCXZ:
		case ZYDIS_MNEMONIC_JECXZ:
		case ZYDIS_MNEMONIC_JKNZD:
		case ZYDIS_MNEMONIC_JKZD:
		case ZYDIS_MNEMONIC_JL:
		case ZYDIS_MNEMONIC_JLE:
		case ZYDIS_MNEMONIC_JMP:
		case ZYDIS_MNEMONIC_JNB:
		case ZYDIS_MNEMONIC_JNBE:
		case ZYDIS_MNEMONIC_JNL:
		case ZYDIS_MNEMONIC_JNLE:
		case ZYDIS_MNEMONIC_JNO:
		case ZYDIS_MNEMONIC_JNP:
		case ZYDIS_MNEMONIC_JNS:
		case ZYDIS_MNEMONIC_JNZ:
		case ZYDIS_MNEMONIC_JO:
		case ZYDIS_MNEMONIC_JP:
		case ZYDIS_MNEMONIC_JRCXZ:
		case ZYDIS_MNEMONIC_JS:
		case ZYDIS_MNEMONIC_JZ:
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], dwRVA, &Address))) {
				ToDisasm.Push(Address);
			} else {
				LOG(Warning, MODULE_VM, "Failed to disassemble jump at %lu\n", dwRVA);
			}
		default:
			break;
		}

		dwRVA = ToDisasm.Pop();
	} while (ToDisasm.Size());

	return ret;
}