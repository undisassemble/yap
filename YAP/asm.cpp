#include "asm.hpp"
#include "assembler.hpp"

typedef struct {
	BYTE Version : 3;
	BYTE Flags : 5;
	BYTE SizeProlog;
	BYTE NumUnwindCodes;
	BYTE FrameReg : 4;
	BYTE FrameRegOff : 4;
} UNWIND_INFO;

typedef struct {
	BYTE Offset;
	BYTE OpCode : 4;
	BYTE OpInfo : 4;
} UNWIND_CODE;

typedef struct {
	DWORD BeginAddress;
	DWORD EndAddress;
	DWORD HandlerAddress;
	DWORD JumpTarget;
} C_SCOPE_TABLE;

char* ZydisErrorToString(ZyanStatus Status) {
	switch (Status) {
	case ZYDIS_STATUS_NO_MORE_DATA:
		return "ZYDIS_STATUS_NO_MORE_DATA";
	case ZYDIS_STATUS_DECODING_ERROR:
		return "ZYDIS_STATUS_DECODING_ERROR";
	case ZYDIS_STATUS_INSTRUCTION_TOO_LONG:
		return "ZYDIS_STATUS_INSTRUCTION_TOO_LONG";
	case ZYDIS_STATUS_BAD_REGISTER:
		return "ZYDIS_STATUS_BAD_REGISTER";
	case ZYDIS_STATUS_ILLEGAL_LOCK:
		return "ZYDIS_STATUS_ILLEGAL_LOCK";
	case ZYDIS_STATUS_ILLEGAL_LEGACY_PFX:
		return "ZYDIS_STATUS_ILLEGAL_LEGACY_PFX";
	case ZYDIS_STATUS_ILLEGAL_REX:
		return "ZYDIS_STATUS_ILLEGAL_REX";
	case ZYDIS_STATUS_INVALID_MAP:
		return "ZYDIS_STATUS_INVALID_MAP";
	case ZYDIS_STATUS_MALFORMED_EVEX:
		return "ZYDIS_STATUS_MALFORMED_EVEX";
	case ZYDIS_STATUS_MALFORMED_MVEX:
		return "ZYDIS_STATUS_MALFORMED_MVEX";
	case ZYDIS_STATUS_INVALID_MASK:
		return "ZYDIS_STATUS_INVALID_MASK";
	case ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION:
		return "ZYDIS_STATUS_IMPOSSIBLE_INSTRUCTION";
	case ZYAN_STATUS_INVALID_ARGUMENT:
		return "ZYAN_STATUS_INVALID_ARGUMENT";
	default:
		return NULL;
	}
}

bool IsInstructionCF(_In_ ZydisMnemonic mnemonic) {
	switch (mnemonic) {
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
	case ZYDIS_MNEMONIC_LOOP:
	case ZYDIS_MNEMONIC_LOOPE:
	case ZYDIS_MNEMONIC_LOOPNE:
	case ZYDIS_MNEMONIC_CALL:
		return true;
	default:
		return false;
	}
}

bool IsInstructionMemory(_In_ ZydisDecodedInstruction* pInstruction, _In_ ZydisDecodedOperand* pOperand) {
	return IsInstructionCF(pInstruction->mnemonic) || pOperand->type == ZYDIS_OPERAND_TYPE_MEMORY;
}

Asm::Asm() : PE(false) {}

Asm::Asm(_In_ char* sFileName) : PE(sFileName) {
	if (Status) return;
	ZydisDecoderInit(&Decoder, GetMachine(), ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

Asm::Asm(_In_ HANDLE hFile) : PE(hFile) {
	ZydisDecoderInit(&Decoder, GetMachine(), ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < SectionHeaders.Size(); i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.NewRVA = sec.OldRVA = SectionHeaders[i].VirtualAddress;
		sec.OldSize = SectionHeaders[i].Misc.VirtualSize;
		Sections.Push(sec);
	}
}

Asm::~Asm() {
	for (int i = 0; i < Sections.Size(); i++) if (Sections[i].Lines) {
		Sections[i].Lines->Release();
		free(Sections[i].Lines);
	}
	Sections.Release();
	JumpTables.Release();
	FunctionRanges.Release();
}

DWORD Asm::GetNextOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex) {
	Vector<Line>* Lines = Sections[dwSec].Lines;
	if (!Lines || Lines->Size() <= dwIndex) return _UI32_MAX;
	
	for (; dwIndex < Lines->Size(); dwIndex++) {
		if (Lines->At(dwIndex).OldRVA) return dwIndex;
	}

	return _UI32_MAX;
}

DWORD Asm::GetPrevOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex) {
	Vector<Line>* Lines = Sections[dwSec].Lines;
	if (!Lines) return _UI32_MAX;

	for (;; dwIndex--) {
		if (Lines->At(dwIndex).OldRVA) return dwIndex;
		if (!dwIndex) return _UI32_MAX;
	}

	return _UI32_MAX;
}

DWORD Asm::FindSectionIndex(_In_ DWORD dwRVA) {
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	for (DWORD i = 0; i < Sections.Size(); i++) {
		if (Sections[i].OldRVA <= dwRVA && Sections[i].OldRVA + Sections[i].OldSize >= dwRVA) {
			DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
			return i;
		}
	}
	DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
	return _UI32_MAX;
}

DWORD Asm::FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	if (dwSec > Sections.Size()) return _UI32_MAX;
	Vector<Line>* Lines = Sections[dwSec].Lines;

	// If no lines exist, it will just be the first line
	if (!Lines || !Lines->Size())
		return _UI32_MAX;

	// Check bounds
	if (Lines->At(0).OldRVA && dwRVA >= Lines->At(0).OldRVA && dwRVA < Lines->At(0).OldRVA + GetLineSize(Lines->At(0)))
		return 0;
	if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA >= Lines->At(Lines->Size() - 1).OldRVA && dwRVA < Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size() - 1;

	if (Lines->Size() == 1)
		return _UI32_MAX;

	// Search
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	size_t PrevI = 0;
	while (szMin <= szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		if (szMin + 1 == szMax) {
			i = szMin = szMax;
		}
		i = GetNextOriginal(dwSec, i);
		if (i >= szMax || i == PrevI) i = GetNextOriginal(dwSec, szMin + 1);
		if (i == PrevI) break;

		// Check index
		if (dwRVA >= Lines->At(i).OldRVA && dwRVA < Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
			return i;
		}

		if (dwRVA >= Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// Shift range
			szMax = i;
		}

		else {
			DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
			return _UI32_MAX;
		}
		PrevI = i;
	}

	DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
	return _UI32_MAX;
}

DWORD Asm::FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	Vector<Line>* Lines = Sections[dwSec].Lines;

	// If no lines exist, it will just be the first line
	if (!Lines->Size())
		return 0;

	// Check bounds
	if (Lines->At(0).OldRVA && dwRVA < Lines->At(0).OldRVA)
		return 0;
	else if (Lines->At(0).OldRVA && dwRVA == Lines->At(0).OldRVA)
		return _UI32_MAX - 1;
	if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA >= Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size();
	else if (Lines->At(Lines->Size() - 1).OldRVA && dwRVA == Lines->At(Lines->Size() - 1).OldRVA)
		return _UI32_MAX - 1;

	// Search
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	while (szMin < szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		i = GetNextOriginal(dwSec, i);
		if (i == _UI32_MAX) break;

		if (dwRVA >= Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			// In between
			if (dwRVA < Lines->At(GetNextOriginal(dwSec, i + 1)).OldRVA) {
				DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
				return GetNextOriginal(dwSec, i + 1);
			}

			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// In between
			if (dwRVA > Lines->At(GetPrevOriginal(dwSec, i - 1)).OldRVA + GetLineSize(Lines->At(GetPrevOriginal(dwSec, i - 1)))) {
				DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
				return i;
			}

			// Shift range
			szMax = i;
		}
		
		else {
			DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
			return _UI32_MAX - 1;
		}
	}

	DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
	return _UI32_MAX;
}

bool Asm::DisasmRecursive(_In_ DWORD dwRVA) {
	Vector<DWORD> ToDisasm; // To prevent stack overflows on big programs, this function is a lie and is not actually recursive, sue me
	ToDisasm.Push(dwRVA);
	//Vector<DWORD> Funcs; // Vector of indexes
	//Funcs.Push(0);
	//Vector<FunctionRange> ranges;
	//Vector<bool> verified;
	//FunctionRange range;
	//range.dwStart = dwRVA;
	//range.dwSize = 0;
	//ranges.Push(range);
	//verified.Push(false);
	//DWORD CurrentFunc = 0;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
	Vector<Line>* Lines;
	Vector<Line> TempLines;
	DWORD SectionIndex;
	char FormattedBuf[128];
	ZydisFormatter Formatter;
	ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	do {
		//ranges.Replace(CurrentFunc, range);

		// Setup
		dwRVA = ToDisasm.Pop();
		//CurrentFunc = Funcs.Pop();
		//range = ranges[CurrentFunc];
		TempLines.Release();
		if (!dwRVA) {
			LOG(Warning, MODULE_REASSEMBLER, "Skipping NULL RVA\n");
			continue;
		}
		SectionIndex = FindSectionIndex(dwRVA);
		if (SectionIndex > Sections.Size()) {
			LOG(Failed, MODULE_REASSEMBLER, "Failed to find index of section at %u\n", dwRVA);
			return false;
		}
		Lines = Sections[SectionIndex].Lines;
		Buffer RawBytes = { 0 };
		{
			RawBytes = SectionData[FindSectionByRVA(dwRVA)];
			IMAGE_SECTION_HEADER Header = SectionHeaders[FindSectionByRVA(dwRVA)];
			if (!RawBytes.pBytes || !RawBytes.u64Size || !Header.Misc.VirtualSize) {
				LOG(Warning, MODULE_REASSEMBLER, "Failed to get bytes for RVA %lu\n", dwRVA);
				continue;
			}
			RawBytes.pBytes += dwRVA - Header.VirtualAddress;
			RawBytes.u64Size -= dwRVA - Header.VirtualAddress;
		}

		// Locate current position in index
		DWORD i = FindPosition(SectionIndex, dwRVA);
		if (i > Lines->Size()) {
			if (i == _UI32_MAX - 1) continue; // Already disassembled
			LOG(Failed, MODULE_REASSEMBLER, "Failed to find position for instruction at %u\n", dwRVA);
			return false;
		}

		// Start disassembling
		Line CraftedLine;
		CraftedLine.Type = Decoded;
		while (RawBytes.u64Size && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, RawBytes.pBytes, RawBytes.u64Size, &CraftedLine.Decoded.Instruction, Operands))) {
			CraftedLine.Decoded.Instruction.operand_count = CraftedLine.Decoded.Instruction.operand_count_visible;
			memcpy(CraftedLine.Decoded.Operands, Operands, sizeof(ZydisDecodedOperand) * CraftedLine.Decoded.Instruction.operand_count_visible);
			CraftedLine.OldRVA = dwRVA;
			TempLines.Push(CraftedLine);

			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
				//verified.Replace(CurrentFunc, true); // verify if function returns
				//if (dwRVA + CraftedLine.Decoded.Instruction.length > range.dwSize + range.dwStart) {
					//range.dwSize = dwRVA - range.dwStart + CraftedLine.Decoded.Instruction.length;
				//}
				break;
			}

			// Check if is jump table
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_LEA && CraftedLine.Decoded.Operands[1].mem.base == ZYDIS_REGISTER_RIP) {
				DWORD trva = 0, rva = 0, disp = 0, odisp = 0;
				{
					uint64_t r;
					ZydisCalcAbsoluteAddress(&CraftedLine.Decoded.Instruction, &CraftedLine.Decoded.Operands[1], CraftedLine.OldRVA, &r);
					disp = odisp = r;
				}

				do {
					rva = ReadRVA<DWORD>(disp);
					if (!rva) break;
					trva = odisp + rva;
					if (!(trva != 0xCCCCCCCC && trva >= Sections[SectionIndex].OldRVA && trva < Sections[SectionIndex].OldRVA + Sections[SectionIndex].OldSize)) break;
					if (!JumpTables.Includes(trva)) JumpTables.Push(trva);
					Line TempJumpTable = { 0 };
					TempJumpTable.OldRVA = disp;
					TempJumpTable.Type = JumpTable;
					TempJumpTable.bRelative = true;
					TempJumpTable.JumpTable.Value = rva;
					TempJumpTable.JumpTable.Base = odisp;
					WORD SecIndex = FindSectionIndex(disp);
					DWORD i = FindPosition(SecIndex, disp);
					if (i == _UI32_MAX) {
						LOG(Failed, MODULE_REASSEMBLER, "Failed to find position for %#x\n", disp);
						return false;
					}
					if (i != _UI32_MAX - 1) Sections[SecIndex].Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				} while (1);
			}
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV && CraftedLine.Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[1].mem.scale == 4 && CraftedLine.Decoded.Operands[1].mem.base != ZYDIS_REGISTER_RIP) {
				DWORD rva = 0;
				DWORD disp = CraftedLine.Decoded.Operands[1].mem.disp.value;
				while ((rva = ReadRVA<DWORD>(disp)) != 0xCCCCCCCC && rva >= Sections[SectionIndex].OldRVA && rva < Sections[SectionIndex].OldRVA + Sections[SectionIndex].OldSize) {
					if (!JumpTables.Includes(rva)) JumpTables.Push(rva);
					Line TempJumpTable = { 0 };
					TempJumpTable.OldRVA = disp;
					TempJumpTable.Type = JumpTable;
					TempJumpTable.JumpTable.Value = rva;
					WORD SecIndex = FindSectionIndex(disp);
					DWORD i = FindPosition(SecIndex, disp);
					if (i == _UI32_MAX) {
						LOG(Failed, MODULE_REASSEMBLER, "Failed to find position for %#x\n", disp);
						return false;
					}
					if (i != _UI32_MAX - 1) Sections[SecIndex].Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				}
			}
 
			if (IsInstructionCF(CraftedLine.Decoded.Instruction.mnemonic)) {
				// Make sure the operand is an address, dont jump to registers yet
				if ((CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) || (CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && (CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_RIP && CraftedLine.Decoded.Operands[0].mem.base != ZYDIS_REGISTER_NONE))) {
					ZydisFormatterFormatInstruction(&Formatter, &CraftedLine.Decoded.Instruction, CraftedLine.Decoded.Operands, CraftedLine.Decoded.Instruction.operand_count_visible, FormattedBuf, 128, GetBaseAddress() + dwRVA, NULL);
					LOG(Warning, MODULE_REASSEMBLER, "Can\'t resolve jump-to address at %#x (%s)\n", dwRVA, FormattedBuf);
				}

				// Calculate absolute address
				else {
					uint64_t u64Referencing;
					if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&CraftedLine.Decoded.Instruction, &CraftedLine.Decoded.Operands[0], CraftedLine.OldRVA, &u64Referencing))) {
						LOG(Failed, MODULE_REASSEMBLER, "Failed to disassemble instruction at 0x%p\n", GetBaseAddress() + CraftedLine.OldRVA);
						TempLines.Release();
						return false;
					}

					// If address is a pointer, use the address stored at that address (if possible)
					if (CraftedLine.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
						// If address is an import we dont want to disassemble it
						IMAGE_DATA_DIRECTORY ImportDir = Decoder.machine_mode == ZYDIS_MACHINE_MODE_LONG_64 ? NTHeaders.x64.OptionalHeader.DataDirectory[1] : NTHeaders.x86.OptionalHeader.DataDirectory[1];
						if (u64Referencing >= ImportDir.VirtualAddress && u64Referencing < (uint64_t)ImportDir.VirtualAddress + ImportDir.Size) {
							u64Referencing = 0;
						}

						// Find the section (u64Referencing is absolute, not an RVA, so we have to translate it manually)
						else {
							WORD wContainingIndex = FindSectionByRVA(u64Referencing);
							if (wContainingIndex >= SectionHeaders.Size()) {
								LOG(Failed, MODULE_REASSEMBLER, "Failed to disassemble code pointed to at %#x\n", u64Referencing);
								TempLines.Release();
								return false;
							}
							
							// Extract the address
							Line insert;
							insert.OldRVA = u64Referencing;
							u64Referencing = ReadRVA<uint64_t>(u64Referencing);
							if (!u64Referencing) {
								LOG(Warning, MODULE_REASSEMBLER, "Failed to retrieve address at VA 0x%p\n", u64Referencing);
								u64Referencing = 0;
							}
							
							// Insert address
							insert.Type = Pointer;
							insert.Pointer.IsAbs = true;
							insert.Pointer.Abs = u64Referencing;
							// At this point I got contacted by a discord scammer and decided to bait them instead of coding, continue here please!
							// Im back :)
							{
								WORD wInsertAt = FindPosition(wContainingIndex, insert.OldRVA);
								if (wInsertAt == _UI16_MAX) {
									LOG(Warning, MODULE_REASSEMBLER, "Failed to find position to insert line at 0x%p\n", GetBaseAddress() + insert.OldRVA);
								} else if (wInsertAt != _UI16_MAX - 1) {
									Sections[wContainingIndex].Lines->Insert(wInsertAt, insert);
								}
							}

							u64Referencing -= GetBaseAddress();
						}
					}

					if (u64Referencing) {
						// Disassemble the address (if good)
						IMAGE_SECTION_HEADER Header = SectionHeaders[FindSectionByRVA(u64Referencing)];
						if (Header.Characteristics & IMAGE_SCN_MEM_EXECUTE && Header.SizeOfRawData > u64Referencing - Header.VirtualAddress) {
							if (!ToDisasm.Includes(u64Referencing)) {
								ToDisasm.Push(u64Referencing);
								if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && !Functions.Includes(u64Referencing)) {
									Functions.Push(u64Referencing);
									//Funcs.Push(verified.Size());
									//verified.Push(false);
									//FunctionRange temp;
									//temp.dwStart = u64Referencing;
									//temp.dwSize = 0;
									//ranges.Push(temp);
								} else {
									//Funcs.Push(CurrentFunc);
								}
							}
						}

						// Exit if unconditional
						if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
							break;
						}
					}
				}
			}

			// Adjust vars
			//if (dwRVA < range.dwStart) {
				//range.dwStart = dwRVA;
			//}
			dwRVA += CraftedLine.Decoded.Instruction.length;
			RawBytes.u64Size -= CraftedLine.Decoded.Instruction.length;
			RawBytes.pBytes += CraftedLine.Decoded.Instruction.length;
			//if (dwRVA > range.dwSize + range.dwStart) {
				//range.dwSize = dwRVA - range.dwStart;
			//}

			// Stop disassembly if the next instruction has already been disassembled
			if (i < Lines->Size() && Lines->At(i).OldRVA == dwRVA) {
				break;
			}
		}

		// Insert lines
		Lines->Insert(i, TempLines);
	} while (ToDisasm.Size());
	//ranges.Replace(CurrentFunc, range);

	// Store verified functions
	//for (int i = 0; i < verified.Size(); i++) if (verified[i]) {
		//FunctionRanges.Push(ranges[i]);
	//}

	ToDisasm.Release();
	//Funcs.Release();
	//verified.Release();
	//ranges.Release();
	return true;
}

bool Asm::CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr) {
	// Fix addresses mode
	if (bFixAddr) {
		pFunc->BeginAddress = TranslateOldAddress(pFunc->BeginAddress);
		pFunc->EndAddress = TranslateOldAddress(pFunc->EndAddress);
		pFunc->UnwindData = TranslateOldAddress(pFunc->UnwindData);
	} else {
		// Disassemble
		if (pFunc->BeginAddress && !DisasmRecursive(pFunc->BeginAddress))
			return false;
	}

	// Check unwind info for function
	UNWIND_INFO UnwindInfo = ReadRVA<UNWIND_INFO>(pFunc->UnwindData);
	if (UnwindInfo.NumUnwindCodes & 1) UnwindInfo.NumUnwindCodes++;

	// Check for handler
	if (UnwindInfo.Flags & UNW_FLAG_EHANDLER || UnwindInfo.Flags & UNW_FLAG_UHANDLER) {
		
		// Handler RVA
		DWORD RVA = ReadRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE));
		
		// Scope table
		Vector<C_SCOPE_TABLE> Tables;
		for (int i = 0, n = ReadRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD)); i < n; i++) {
			C_SCOPE_TABLE temp = ReadRVA<C_SCOPE_TABLE>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2 + sizeof(C_SCOPE_TABLE) * i);
			Tables.Push(temp);
		}

		if (bFixAddr) {
			WriteRVA<DWORD>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE), TranslateOldAddress(RVA));
			
			// Scope table
			for (int i = 0; i < Tables.Size(); i++) {
				C_SCOPE_TABLE t = Tables[i];
				t.BeginAddress = TranslateOldAddress(Tables[i].BeginAddress);
				t.EndAddress = TranslateOldAddress(Tables[i].EndAddress);
				t.HandlerAddress = TranslateOldAddress(Tables[i].HandlerAddress);
				t.JumpTarget = TranslateOldAddress(Tables[i].JumpTarget);
				WriteRVA<C_SCOPE_TABLE>(pFunc->UnwindData + sizeof(UNWIND_INFO) + UnwindInfo.NumUnwindCodes * sizeof(UNWIND_CODE) + sizeof(DWORD) * 2 + sizeof(C_SCOPE_TABLE) * i, t);
			}
		} else {
			if (RVA && !DisasmRecursive(RVA)) return false;
			
			// Scope table
			for (int i = 0; i < Tables.Size(); i++) {
				if (Tables[i].BeginAddress && !DisasmRecursive(Tables[i].BeginAddress)) return false;
				if (Tables[i].EndAddress && !DisasmRecursive(Tables[i].EndAddress)) return false;
				if (Tables[i].HandlerAddress && !DisasmRecursive(Tables[i].HandlerAddress)) return false;
				if (Tables[i].JumpTarget && !DisasmRecursive(Tables[i].JumpTarget)) return false;
			}
		}
		Tables.Release();
	}
	return true;
}

bool Asm::Disassemble() {
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	if (Status) {
		LOG(Failed, MODULE_REASSEMBLER, "Could not begin disassembly, as no binary is loaded (%hhd)\n", Status);
		return false;
	}
	LOG(Info, MODULE_REASSEMBLER, "Beginning disassembly\n");

	// Insert known absolutes
	Vector<DWORD> relocs = GetRelocations();
	for (int i = 0; i < relocs.Size(); i++) {
		Line insert;
		insert.OldRVA = relocs[i];
		insert.Type = Pointer;
		insert.Pointer.IsAbs = true;
		insert.Pointer.Abs = ReadRVA<uint64_t>(insert.OldRVA);
		WORD wContainingSec = FindSectionIndex(insert.OldRVA);
		WORD wIndex = FindPosition(wContainingSec, insert.OldRVA);
		if (wIndex == _UI16_MAX || wContainingSec == _UI16_MAX) {
			LOG(Warning, MODULE_REASSEMBLER, "Failed to find position to insert line at 0x%p\n", GetBaseAddress() + insert.OldRVA);
			continue;
		}
		Sections[wContainingSec].Lines->Insert(wIndex, insert);
	}

	// Insert known RVAs
	{
		Line insert;
		insert.Type = Pointer;
		insert.Pointer.IsAbs = false;

		// IAT
		if (NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress && NTHeaders.x64.OptionalHeader.DataDirectory[1].Size) {
			// Insert entries
			IAT_ENTRY entry = { 0 };
			insert.OldRVA = NTHeaders.x64.OptionalHeader.DataDirectory[1].VirtualAddress;
			WORD wSecIndex = FindSectionIndex(insert.OldRVA);
			WORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				LOG(Failed, MODULE_REASSEMBLER, "Failed to insert IAT!\n");
				return false;
			}
			do {
				ReadRVA(insert.OldRVA, &entry, sizeof(IAT_ENTRY));
				insert.Pointer.RVA = entry.LookupRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD) * 3;
				insert.Pointer.RVA = entry.NameRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
				insert.Pointer.RVA = entry.ThunkRVA;
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			} while (entry.LookupRVA && entry.NameRVA);
			
			// Insert names
			IAT_ENTRY* pEntries = GetIAT();
			for (int i = 0; pEntries && pEntries[i].LookupRVA; i++) {
				// Begin
				insert.OldRVA = pEntries[i].LookupRVA;
				WORD wSecIndex = FindSectionIndex(insert.OldRVA);
				WORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
				if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
					LOG(Failed, MODULE_REASSEMBLER, "Failed to insert IAT!\n");
					return false;
				}
				if (wIndex == _UI32_MAX - 1) {
					continue;
				}

				// Do
				do {
					insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
					Sections[wSecIndex].Lines->Insert(wIndex, insert);
					wIndex++;
					insert.OldRVA += sizeof(uint64_t);
				} while (insert.Pointer.RVA);
			}
		}

		// Exports
		if (NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress && NTHeaders.x64.OptionalHeader.DataDirectory[0].Size) {
			IMAGE_EXPORT_DIRECTORY ExportTable = ReadRVA<IMAGE_EXPORT_DIRECTORY>(NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress);
			insert.OldRVA = NTHeaders.x64.OptionalHeader.DataDirectory[0].VirtualAddress + sizeof(DWORD) * 7;
			WORD wSecIndex = FindSectionIndex(insert.OldRVA);
			WORD wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				LOG(Failed, MODULE_REASSEMBLER, "Failed to insert exports!\n");
				return false;
			}
			insert.Pointer.RVA = ExportTable.AddressOfFunctions;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNames;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNameOrdinals;
			Sections[wSecIndex].Lines->Insert(wIndex, insert);

			// Functions
			insert.OldRVA = ExportTable.AddressOfFunctions;
			wSecIndex = FindSectionIndex(insert.OldRVA);
			wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				LOG(Failed, MODULE_REASSEMBLER, "Failed to insert exports!\n");
				return false;
			}
			for (int i = 0; i < ExportTable.NumberOfFunctions; i++) {
				insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			}

			// Names
			insert.OldRVA = ExportTable.AddressOfNames;
			wSecIndex = FindSectionIndex(insert.OldRVA);
			wIndex = FindPosition(wSecIndex, insert.OldRVA);
			if (wIndex == _UI32_MAX || wSecIndex == _UI32_MAX) {
				LOG(Failed, MODULE_REASSEMBLER, "Failed to insert exports!\n");
				return false;
			}
			for (int i = 0; i < ExportTable.NumberOfNames; i++) {
				insert.Pointer.RVA = ReadRVA<DWORD>(insert.OldRVA);
				Sections[wSecIndex].Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			}
		}
	}

	// Initialize Zydis
	ZydisDecoderInit(&Decoder, GetMachine(), x86 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);

	// Disassemble entry point
	if (!DisasmRecursive(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint)) {
		return false;
	}
	LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled Entry Point (0x%p)\n", GetBaseAddress() + NTHeaders.x64.OptionalHeader.AddressOfEntryPoint);

	// Error check (TEMPORARY)
	{
		Vector<Line>* Lines = Sections[FindSectionIndex(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint)].Lines;
		for (size_t i = 0; i < Lines->Size() - 1; i++) {
			if (Lines->At(i).OldRVA + GetLineSize(Lines->At(i)) > Lines->At(i + 1).OldRVA) {
				LOG(Failed, MODULE_REASSEMBLER, "Peepee poopoo (0x%p + %u -> 0x%p)\n", GetBaseAddress() + Lines->At(i).OldRVA, GetLineSize(Lines->At(i)), GetBaseAddress() + Lines->At(i + 1).OldRVA);
				return false;
			}
		}
	}

	// Disassemble TLS callbacks
	uint64_t* pCallbacks = GetTLSCallbacks();
	if (pCallbacks) {
		for (WORD i = 0; pCallbacks[i]; i++) {
			if (!DisasmRecursive(pCallbacks[i] - GetBaseAddress())) {
				return false;
			}
			LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled TLS Callback (0x%p)\n", pCallbacks[i]);
		}
	}

	// Disassemble exports
	{
		Vector<DWORD> Exports = GetExportedFunctionRVAs();
		Vector<char*> ExportNames = GetExportedFunctionNames();
		for (int i = 0; i < Exports.Size(); i++) {
			if (!DisasmRecursive(Exports[i])) {
				return false;
			}
			LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled exported function \'%s\'\n", ExportNames[i]);
		}
	}
	LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled Exports\n");

	// Disassemble exception dir
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = SectionData[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		IMAGE_SECTION_HEADER ExcSecHeader = SectionHeaders[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		if (ExcData.pBytes && ExcSecHeader.VirtualAddress) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - ExcSecHeader.VirtualAddress);
			for (uint32_t i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				if (!CheckRuntimeFunction(&pArray[i])) {
					return false;
				}
			}
		}
	}
	LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled Exception Directory\n");

	// Disassemble jump tables
	{
		DWORD osize = JumpTables.Size();
		while (JumpTables.Size()) {
			if (!DisasmRecursive(JumpTables.Pop()))
				return false;
		}
		if (osize) LOG(Success, MODULE_REASSEMBLER, "Disassembled %d switch cases\n", osize);
	}

	DEBUG_ONLY(Data.TimeSpentDisassembling = GetTickCount64() - TickCount - Data.TimeSpentSearching - Data.TimeSpentInserting);
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent disassembling: %llu\n", Data.TimeSpentDisassembling));
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent searching: %llu\n", Data.TimeSpentSearching));
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent inserting: %llu\n", Data.TimeSpentInserting));
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Number of instructions: %llu\n", GetNumLines()));
	//LOG(Info, MODULE_REASSEMBLER, "Discovered %d functions\n", FunctionRanges.Size());
	LOG(Success, MODULE_REASSEMBLER, "Finished disassembly\n");

	// Insert missing data + padding
	DEBUG_ONLY(uint64_t OldTimeSpentSeaching = Data.TimeSpentSearching);
	DEBUG_ONLY(TickCount = GetTickCount64());
	Line line;
	LOG(Info_Extended, MODULE_REASSEMBLER, "Filling gaps\n");
	for (int i = 0; i < Sections.Size(); i++) {
		LOG(Info_Extended, MODULE_REASSEMBLER, "Filling section %.8s (%llu lines)\n", SectionHeaders[i].Name, Sections[i].Lines->Size());

		// Incase section holds no lines
		if (!Sections[i].Lines->Size()) {	
			line.Type = Embed;
			line.OldRVA = Sections[i].OldRVA;
			if (Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) {
				line.Embed.Size = Sections[i].OldSize;
				Sections[i].Lines->Push(line);
				continue;
			}
			line.Embed.Size = SectionHeaders[i].SizeOfRawData;
			if (line.OldRVA && line.Embed.Size) Sections[i].Lines->Push(line);
			line.Type = Padding;
			line.OldRVA += line.Embed.Size;
			line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
			if (line.OldRVA && line.Padding.Size) Sections[i].Lines->Push(line);
			continue;
		}

		// Insert prepended data
		line.Type = Embed;
		if (Sections[i].Lines->At(0).OldRVA > Sections[i].OldRVA) {
			line.OldRVA = Sections[i].OldRVA;
			line.Embed.Size = Sections[i].Lines->At(0).OldRVA - Sections[i].OldRVA;
			Sections[i].Lines->Insert(0, line);
		} else if (Sections[i].Lines->At(0).OldRVA < Sections[i].OldRVA) {
			LOG(Warning, MODULE_REASSEMBLER, "First line in section %d begins below the section (you should *hopefully* never see this)\n", i);
		}

		// Insert embedded data
		for (int j = 0; j < Sections[i].Lines->Size() - 1; j++) {
			line.OldRVA = Sections[i].Lines->At(j).OldRVA + GetLineSize(Sections[i].Lines->At(j));
			if (line.OldRVA < Sections[i].Lines->At(j + 1).OldRVA) {
				line.Embed.Size = Sections[i].Lines->At(j + 1).OldRVA - line.OldRVA;
				Sections[i].Lines->Insert(j + 1, line);
				j++;
			}
		}

		// Insert ending data
		line.OldRVA = Sections[i].Lines->At(Sections[i].Lines->Size() - 1).OldRVA + GetLineSize(Sections[i].Lines->At(Sections[i].Lines->Size() - 1));
		if (line.OldRVA - Sections[i].OldRVA < SectionHeaders[i].SizeOfRawData && line.OldRVA - Sections[i].OldRVA < Sections[i].OldSize) {
			line.Embed.Size = ((Sections[i].OldSize < SectionHeaders[i].SizeOfRawData) ? Sections[i].OldSize : SectionHeaders[i].SizeOfRawData) - (line.OldRVA - Sections[i].OldRVA);
			Sections[i].Lines->Push(line);
		}

		// Insert padding
		line.Type = Padding;
		line.OldRVA = Sections[i].Lines->At(Sections[i].Lines->Size() - 1).OldRVA + GetLineSize(Sections[i].Lines->At(Sections[i].Lines->Size() - 1));
		line.Padding.Size = Sections[i].OldSize - (line.OldRVA - Sections[i].OldRVA);
		if (line.OldRVA && line.Padding.Size) Sections[i].Lines->Push(line);
	}
	LOG(Success, MODULE_REASSEMBLER, "Filled gaps\n");
	DEBUG_ONLY(Data.TimeSpentFilling = GetTickCount64() - TickCount - (Data.TimeSpentSearching - OldTimeSpentSeaching));

	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent inserting: %llu\n", Data.TimeSpentInserting));
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent filling gaps: %llu\n", Data.TimeSpentFilling));
	LOG(Success, MODULE_REASSEMBLER, "Finished disassembly\n");
	return true;
}

bool Asm::Analyze() {
	// Function ranges
	if (Options.Packing.bPartialUnpacking) {
		FunctionRange range = { 0 };
		FunctionRanges.Release();
		Vector<DWORD> Done;
		Vector<DWORD> ToDo;
		Vector<Line>* pLines = NULL;
		DWORD dwRVA;
		DWORD index;
		IMAGE_DATA_DIRECTORY IAT = NTHeaders.x64.OptionalHeader.DataDirectory[1];

		// Add entries
		if (!Functions.Includes(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint)) Functions.Push(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint);
		for (uint64_t* pTLS = GetTLSCallbacks(); pTLS && *pTLS; pTLS++) {
			if (!Functions.Includes(*pTLS - GetBaseAddress())) Functions.Push(*pTLS - GetBaseAddress());
		}

		// Do the things
		for (int i = 0; i < Functions.Size(); i++) {
			// Setup
			ToDo.Release();
			Done.Release();
			dwRVA = Functions[i];
			ToDo.Push(dwRVA);
			range.Entries.nItems = 0;
			range.Entries.raw.pBytes = NULL;
			range.Entries.raw.u64Size = 0;
			range.Entries.Push(dwRVA);
			range.dwStart = dwRVA;
			range.dwSize = 0;

			// Walk through function
			do {
				// Setup
				dwRVA = ToDo.Pop();
				pLines = NULL;
				{
					DWORD secIndex = FindSectionIndex(dwRVA);
					pLines = Sections[secIndex].Lines;
					if (!pLines) {
						LOG(Warning, MODULE_REASSEMBLER, "Line not found for RVA 0x%08x\n", dwRVA);
						continue;
					}
					index = FindIndex(secIndex, dwRVA);
					if (index == _UI32_MAX) {
						LOG(Warning, MODULE_REASSEMBLER, "Section not found for RVA 0x%08x\n", dwRVA);
						continue;
					}
				}

				while (1) {
					bool bExit = false;
					// Find end cases
					if (Done.Includes(pLines->At(index).OldRVA) || (!range.Entries.Includes(pLines->At(index).OldRVA) && Functions.Includes(pLines->At(index).OldRVA))) {
						if (dwRVA != pLines->At(index).OldRVA && pLines->At(index).OldRVA + GetLineSize(pLines->At(index)) > range.dwStart + range.dwSize) {
							range.dwSize = (pLines->At(index).OldRVA + GetLineSize(pLines->At(index))) - range.dwStart;
						}
						break;
					}

					// CF stuff
					if (pLines->At(index).Type == Decoded && IsInstructionCF(pLines->At(index).Decoded.Instruction.mnemonic) && pLines->At(index).Decoded.Instruction.mnemonic != ZYDIS_MNEMONIC_CALL) {
						if (pLines->At(index).Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
							bExit = true;
						}
						uint64_t r = 0;
						ZydisCalcAbsoluteAddress(&pLines->At(index).Decoded.Instruction, &pLines->At(index).Decoded.Operands[0], pLines->At(index).OldRVA, &r);
						if (!r) {
							LOG(Warning, MODULE_REASSEMBLER, "Failed to calculate jump-to address at 0x%08x\n", pLines->At(index).OldRVA);
						} else if (!Done.Includes(r) && !Functions.Includes(r) && !(IAT.VirtualAddress && IAT.Size && r >= IAT.VirtualAddress && r < IAT.VirtualAddress + IAT.Size)) {
							ToDo.Push(r);
						}
					}

					// Adjust shtuff
					if (pLines->At(index).OldRVA < range.dwStart) {
						range.dwSize += range.dwStart - pLines->At(index).OldRVA;
						range.dwStart = pLines->At(index).OldRVA;
					}
					if (pLines->At(index).OldRVA + GetLineSize(pLines->At(index)) > range.dwStart + range.dwSize) {
						range.dwSize = (pLines->At(index).OldRVA + GetLineSize(pLines->At(index))) - range.dwStart - 1;
					}
					if (bExit || (pLines->At(index).Type == Decoded && pLines->At(index).Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_RET)) {
						break;
					}
					index++;
				}
				Done.Push(dwRVA);
			} while (ToDo.Size());

			FunctionRanges.Push(range);
		}

		// Cleanup
		Done.Release();
		ToDo.Release();
		Functions.Release();

		// Check for invalid functions
		int removed = 0;
		for (int i = 0; i < FunctionRanges.Size(); i++) {
			range = FunctionRanges[i];
			
			// Combined functions (improve this)
			for (int j = 0; j < FunctionRanges.Size(); j++) if (j != i) {
				FunctionRange range2 = FunctionRanges[j];
				
				// Overlapping
				if (range.dwStart <= range2.dwStart && range.dwStart + range.dwSize >= range2.dwStart) {
					FunctionRanges.Remove(i);
					i = -1;
					removed++;
					break;
				}
			}
		}

		// Remove invalid data
		for (int i = 0; i < FunctionRanges.Size(); i++) { 
			FunctionRange range = FunctionRanges[i];
			
			// Functions that are too small
			if (range.dwSize < 17) {
				range.Entries.Release();
				FunctionRanges.Remove(i);
				i--;
				removed++;
				continue;
			}

			// Out-of-bounds entry points
			for (int j = 0; j < range.Entries.Size(); j++) {
				if (range.Entries[j] < range.dwStart || range.Entries[j] >= range.dwStart + range.dwSize) {
					removed++;
					if (range.Entries.Size() == 1) {
						range.Entries.Release();
						FunctionRanges.Remove(i);
						i--;
						break;
					}
				}
			}
		}

		LOG(Info, MODULE_REASSEMBLER, "Found %d compatible functions\n", FunctionRanges.Size());
		LOG(Info_Extended, MODULE_REASSEMBLER, "Removed %d functions\n", removed);
	} else {
		LOG(Info, MODULE_REASSEMBLER, "Skipping function range discovery as results are unused\n");
	}

	LOG(Success, MODULE_REASSEMBLER, "Finished analysis\n");
	return true;
}

/*bool Asm::FixAddresses() {
	LOG(Info, MODULE_REASSEMBLER, "Patching instructions\n");
	Vector<Line>* Lines;
	
	// Fix sections
	AsmSection sec;
	sec = Sections[0];
	sec.NewRVA = sec.OldRVA;
	sec.NewSize = GetAssembledSize(0);
	Sections.Replace(0, sec);
	if (sec.NewRVA != sec.OldRVA || sec.NewSize != sec.OldSize) LOG(Info_Extended, MODULE_REASSEMBLER, "%.8s changed memory range: (%08x - %08x) -> (%08x - %08x)\n", SectionHeaders[0].Name, sec.OldRVA, sec.OldRVA + sec.OldSize, sec.NewRVA, sec.NewRVA + sec.NewSize);
	for (WORD SecIndex = 1; SecIndex < Sections.Size(); SecIndex++) {
		sec = Sections[SecIndex];
		sec.NewRVA = Sections[SecIndex - 1].NewRVA + Sections[SecIndex - 1].NewSize;
		sec.NewRVA += (sec.NewRVA % NTHeaders.x64.OptionalHeader.SectionAlignment) ? NTHeaders.x64.OptionalHeader.SectionAlignment - (sec.NewRVA % NTHeaders.x64.OptionalHeader.SectionAlignment) : 0;
		sec.NewSize = GetAssembledSize(SecIndex);
		Sections.Replace(SecIndex, sec);
		if (sec.NewRVA != sec.OldRVA || sec.NewSize != sec.OldSize) LOG(Info_Extended, MODULE_REASSEMBLER, "%.8s changed memory range: (%08x - %08x) -> (%08x - %08x)\n", SectionHeaders[SecIndex].Name, sec.OldRVA, sec.OldRVA + sec.OldSize, sec.NewRVA, sec.NewRVA + sec.NewSize);
	}
	
	// Set new RVAs
	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Apply new addresses
		Lines = Sections[SecIndex].Lines;
		DWORD dwCurrentAddress = Sections[SecIndex].NewRVA;
		Line line = { 0 };
		for (size_t i = 0; i < Lines->Size(); i++) {
			line = Lines->At(i);
			line.NewRVA = dwCurrentAddress;
			if (line.OldRVA == NTHeaders.x64.OptionalHeader.AddressOfEntryPoint) {
				NTHeaders.x64.OptionalHeader.AddressOfEntryPoint = line.NewRVA;
			}

			// Change short jmps into long jmps
			if (line.Type == Decoded && IsInstructionCF(line.Decoded.Instruction.mnemonic) && line.Decoded.Instruction.mnemonic != ZYDIS_MNEMONIC_CALL && line.Decoded.Instruction.length == 2 && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
				line.Type = Request;
				line.Request.mnemonic = Lines->At(i).Decoded.Instruction.mnemonic;
				line.Request.operand_count = 1;
				line.Request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
				line.Request.address_size_hint = ZYDIS_ADDRESS_SIZE_HINT_NONE;
				line.Request.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;
				line.Request.branch_type = ZYDIS_BRANCH_TYPE_NONE;
				line.Request.branch_width = ZYDIS_BRANCH_WIDTH_NONE;
				line.Request.prefixes = 0;
				line.Request.operand_size_hint = ZYDIS_OPERAND_SIZE_HINT_NONE;
				line.Request.operands[0] = zyasm::Op(Lines->At(i).Decoded.Operands[0]);
				line.bRelative = false;
				line.bRelocate = true;
				ZeroMemory(&line.Request.evex, sizeof(line.Request.evex));
				ZeroMemory(&line.Request.mvex, sizeof(line.Request.mvex));
				ZydisCalcAbsoluteAddress(&Lines->At(i).Decoded.Instruction, &Lines->At(i).Decoded.Operands[0], line.NewRVA, &line.Request.operands[0].imm.u);
			}
			Lines->Replace(i, line);

			// Update address
			DWORD dwChange = GetLineSize(line);
			if (!dwChange) return false;
			dwCurrentAddress += dwChange;
		}
	}

	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Fix relative addresses in asm
		Lines = Sections[SecIndex].Lines;
		Line line;
		uint64_t u64Referencing = 0;
		int64_t i64Off = 0;
		size_t szIndex = 0;
		DWORD _SecIndex, _LineIndex;
		for (size_t k, j, i = 0; i < Lines->Size(); i++) {
			line = Lines->At(i);
			if (line.Type == Decoded) {
				for (j = 0; j < line.Decoded.Instruction.operand_count_visible; j++) {
					if (IsInstructionMemory(&line.Decoded.Instruction, &line.Decoded.Operands[j])) {
						if (IsInstructionCF(line.Decoded.Instruction.mnemonic) && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
							continue;
						if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY && ((line.Decoded.Operands[j].mem.base != ZYDIS_REGISTER_RIP && line.Decoded.Operands[j].mem.base != ZYDIS_REGISTER_NONE) || line.Decoded.Operands[j].mem.index != ZYDIS_REGISTER_NONE))
							continue;

						// Find target
						ZyanStatus status = ZydisCalcAbsoluteAddress(&line.Decoded.Instruction, &line.Decoded.Operands[j], line.OldRVA, &u64Referencing);
						if (ZYAN_FAILED(status)) {
							ZydisFormatter fmt;
							ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
							char op[128];
							ZydisFormatterFormatInstruction(&fmt, &line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, op, 128, GetBaseAddress() + line.OldRVA, NULL);
							LOG(Failed, MODULE_REASSEMBLER, "Failed to calculate absolute address of memory: %s (%s)\n", ZydisErrorToString(status), op);
							return false;
						}

						if (u64Referencing < Sections[0].OldRVA) {
							ZydisFormatter fmt;
							ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
							char op[128];
							ZydisFormatterFormatOperand(&fmt, &line.Decoded.Instruction, &line.Decoded.Operands[j], op, 128, GetBaseAddress() + line.OldRVA, NULL);
							LOG(Warning, MODULE_REASSEMBLER, "Failed to translate address at %p (%s)\n", GetBaseAddress() + line.OldRVA, op);
							continue;
						}
						
						// Calc offset
						i64Off = (int64_t)TranslateOldAddress(u64Referencing) - (line.NewRVA + GetLineSize(line));
						
						// Apply offset
						if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
							line.Decoded.Operands[j].imm.value.s = i64Off;
						} else if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY) {
							line.Decoded.Operands[j].mem.disp.value = i64Off;
						}
					}
				}
			}
			
			// Fix jump tables
			else if (line.Type == JumpTable) {
				// Find target
				u64Referencing = (line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value;

				// Calc offset
				if (line.bRelative) line.JumpTable.Base = TranslateOldAddress(line.JumpTable.Base);
				DWORD NewValue = TranslateOldAddress(u64Referencing);
				if (NewValue == _UI32_MAX) {
					LOG(Failed, MODULE_REASSEMBLER, "Failed to translate switch case targetting %#x\n", u64Referencing);
					return false;
				}
				line.JumpTable.Value = NewValue - (line.bRelative ? line.JumpTable.Base : 0);
			}

			// Absolutes
			else if (line.Type == Pointer) {
				u64Referencing = (line.Pointer.IsAbs ? line.Pointer.Abs - GetBaseAddress() : line.Pointer.RVA);

				// Do the thing
				DWORD NewValue = TranslateOldAddress(u64Referencing);
				if (NewValue == _UI32_MAX) {
					LOG(Failed, MODULE_REASSEMBLER, "Failed to translate pointer pointing at 0x%p\n", GetBaseAddress() + u64Referencing);
					return false;
				}

				// Apply
				if (line.Pointer.IsAbs) {
					line.Pointer.Abs = GetBaseAddress() + NewValue;
				} else {
					line.Pointer.RVA = NewValue;
				}
			}

			// Requests
			else if (line.Type == Request) {
				if (line.bRelative) {
					if (IsInstructionCF(line.Request.mnemonic) && line.Request.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						DWORD index = line.Request.operands[0].imm.u;
						if (index >= Lines->Size()) {
							LOG(Failed, MODULE_REASSEMBLER, "Failed to translate relative insertion\n");
							return false;
						}
						line.Request.operands[0].imm.u = Lines->At(index).NewRVA;
					} else {
						for (int j = 0; j < line.Request.operand_count; j++) {
							if (line.Request.operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY && line.Request.operands[j].mem.base == ZYDIS_REGISTER_RIP) {
								line.Request.operands[j].mem.base = ZYDIS_REGISTER_NONE;
								DWORD index = line.Request.operands[j].mem.displacement;
								if (index >= Lines->Size()) {
									LOG(Failed, MODULE_REASSEMBLER, "Failed to translate relative insertion\n");
									return false;
								}
								line.Request.operands[j].mem.displacement = Lines->At(index).NewRVA;
							}
						}
					}
				} else if (line.bRelocate) {
					if (IsInstructionCF(line.Request.mnemonic) && line.Request.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						line.Request.operands[0].imm.u = TranslateOldAddress(line.Request.operands[0].imm.u);
					} else {
						for (int j = 0; j < line.Request.operand_count; j++) {
							if (line.Request.operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY && line.Request.operands[j].mem.base == ZYDIS_REGISTER_RIP) {
								line.Request.operands[j].mem.base = ZYDIS_REGISTER_NONE;
								line.Request.operands[j].mem.displacement = TranslateOldAddress(line.Request.operands[j].mem.displacement);
							}
						}
					}
				}
			}

			Lines->Replace(i, line);
		}
	}

	// Fix TLS callbacks
	uint64_t* pCallbacks = GetTLSCallbacks();
	if (pCallbacks) {
		for (WORD i = 0; pCallbacks[i] != 0; i++) {
			pCallbacks[i] = GetBaseAddress() + TranslateOldAddress(pCallbacks[i] - GetBaseAddress());
		}
	}
	
	// Fix exception dir
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = SectionData[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		IMAGE_SECTION_HEADER ExcSecHeader = SectionHeaders[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		if (ExcData.pBytes && ExcSecHeader.VirtualAddress) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - ExcSecHeader.VirtualAddress);
			for (DWORD i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				CheckRuntimeFunction(&pArray[i], true);
			}
		}
	}

	// Fix relocations
	Vector<DWORD> Relocations = GetRelocations();
	for (int i = 0; i < Relocations.Size(); i++) {
		Relocations.Replace(i, TranslateOldAddress(Relocations[i]));
	}
	Buffer relocs = GenerateRelocSection(Relocations);
	RemoveData(NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress, NTHeaders.x64.OptionalHeader.DataDirectory[5].Size);
	DWORD SecIndex = FindSectionIndex(NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress);
	Line insert = { 0 };
	insert.Type = RawInsert;
	insert.RawInsert = relocs;
	InsertLine(SecIndex, FindPosition(SecIndex, NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress), insert);
	NTHeaders.x64.OptionalHeader.DataDirectory[5].Size = relocs.u64Size;

	// Fix data dirs
	for (int i = 0; i < 16; i++) {
		if (i == 5) continue;
		NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress = TranslateOldAddress(NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress);
		if (NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress == _UI32_MAX) {
			LOG(Warning, MODULE_REASSEMBLER, "Failed to translate data directory %d\n", i);
			NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress = NTHeaders.x64.OptionalHeader.DataDirectory[i].Size = 0;
		}
	}

	// Fix function ranges
	for (int i = 0; i < FunctionRanges.Size(); i++) {
		FunctionRange range = FunctionRanges[i];
		DWORD end = TranslateOldAddress(range.dwStart + range.dwSize);
		range.dwStart = TranslateOldAddress(range.dwStart);
		range.dwSize = end - range.dwStart;
		for (int j = 0; j < range.Entries.Size(); j++) {
			range.Entries.Replace(j, TranslateOldAddress(range.Entries[j]));
		}
		FunctionRanges.Replace(i, range);
	}

	LOG(Success, MODULE_REASSEMBLER, "Patched instructions\n");
	return true;
}*/

bool Asm::Assemble() {
	// Setup
	LOG(Info, MODULE_REASSEMBLER, "Assembling\n");
	if (!Sections.Size()) return false;
	Vector<Line>* pLines;
	Line line;
	Environment environment;
	environment.setArch(Arch::kX64);
	CodeHolder holder;
	holder.init(environment);
	AsmJitErrorHandler ErrorHandler;
	holder.setErrorHandler(&ErrorHandler);
	ProtectedAssembler a(&holder);
	a.bMutate = a.bSubstitute = false;
	a.MutationLevel = Options.Packing.MutationLevel;

	// Linker data
	RemoveData(NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress, NTHeaders.x64.OptionalHeader.DataDirectory[5].Size);
	Vector<DWORD> XREFs;
	Vector<Label> XREFLabels;
	Vector<Line> LinkLater;
	Vector<QWORD> LinkLaterOffsets;

	// Assemble sections
	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Prepare next section
		AsmSection section = Sections[SecIndex];
		pLines = section.Lines;
		section.NewRVA = a.offset() + SectionHeaders[0].VirtualAddress;
		DWORD rva = section.NewRVA;
		section.NewRawSize = 0;
		section.NewVirtualSize = 0;

		// Assemble lines
		for (int i = 0; i < pLines->Size(); i++) {
			line = pLines->At(i);
			line.NewRVA = rva;
			pLines->Replace(i, line);
			size_t off = a.offset();

			switch (line.Type) {
			case Decoded: {
				// Calculate referenced address
				int rel = -1;
				uint64_t refs = 0;
				Label ah;
				if (IsInstructionCF(line.Decoded.Instruction.mnemonic) && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					rel = 0;
				} else {
					for (int i = 0; i < line.Decoded.Instruction.operand_count_visible; i++) {
						if (line.Decoded.Operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY && (line.Decoded.Operands[i].mem.base == ZYDIS_REGISTER_RIP || line.Decoded.Operands[i].mem.index == ZYDIS_REGISTER_RIP)) {
							rel = i;
							break;
						}
					}
				}
				if (rel >= 0) {
					if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&line.Decoded.Instruction, &line.Decoded.Operands[rel], line.OldRVA, &refs))) {
						LOG(Failed, MODULE_REASSEMBLER, "Failed to calculate reference address of instruction at %p\n", GetBaseAddress() + line.OldRVA);
						return false;
					}
					int loc = XREFs.Find(refs);
					if (loc < 0) {
						XREFs.Push(refs);
						ah = a.newLabel();
						XREFLabels.Push(ah);
					} else {
						ah = XREFLabels[loc];
					}
				}

				// Encode
				a.FromDis(&line, rel >= 0 ? &ah : NULL);
				break;
			}
			case Embed: {
				Buffer buf = { 0 };
				buf.u64Size = line.Embed.Size;
				buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
				ReadRVA(line.OldRVA, buf.pBytes, line.Embed.Size);
				a.embed(buf.pBytes, buf.u64Size);
				buf.Release();
				break;
			}
			case RawInsert:
				a.embed(line.RawInsert.pBytes, line.RawInsert.u64Size);
				break;
			case Padding:
				section.NewVirtualSize += line.Padding.Size;
				a.db(0, line.Padding.Size);
				if (i < pLines->Size() - 1) {
					LOG(Failed, MODULE_REASSEMBLER, "Ran into padding in the middle of a section\n");
					return false;
				}
				break;
			case JumpTable:
				LinkLaterOffsets.Push(a.offset());
				a.dd(0);
				LinkLater.Push(line);
				break;
			case Pointer:
				LinkLaterOffsets.Push(a.offset());
				if (line.Pointer.IsAbs) a.dq(0);
				else a.dd(0);
				LinkLater.Push(line);
			}

			rva += a.offset() - off;
		}

		// Finalize section
		section.NewRawSize = a.offset() - (section.NewRVA - SectionHeaders[0].VirtualAddress);
		section.NewRawSize -= section.NewVirtualSize;
		section.NewVirtualSize += section.NewRawSize;
		if (a.offset() % NTHeaders.x64.OptionalHeader.SectionAlignment) {
			a.db(0, NTHeaders.x64.OptionalHeader.SectionAlignment - a.offset() % NTHeaders.x64.OptionalHeader.SectionAlignment);
		}
		Sections.Replace(SecIndex, section);
	}

	// Link
	LOG(Info, MODULE_REASSEMBLER, "Linking\n");
	if (XREFs.Size() != XREFLabels.Size()) {
		LOG(Failed, MODULE_REASSEMBLER, "This should never happen (XREFs.Size() != XREFLabels.Size())\n");
		return false;
	}
	if (LinkLater.Size() != LinkLaterOffsets.Size()) {
		LOG(Failed, MODULE_REASSEMBLER, "This should never happen part 2 (LinkLater.Size() != LinkLaterOffsets.Size())\n");
		return false;
	}
	for (int i = 0; i < LinkLater.Size(); i++) {
		line = LinkLater[i];
		if (line.Type == JumpTable) {
			if (line.bRelative) line.JumpTable.Base = TranslateOldAddress(line.JumpTable.Base);
			line.JumpTable.Value = TranslateOldAddress((line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value) - (line.bRelative ? line.JumpTable.Base : 0);
			*reinterpret_cast<DWORD*>(holder.textSection()->buffer().data() + LinkLaterOffsets[i]) = line.JumpTable.Value;
		} else if (line.Type == Pointer) {
			if (line.Pointer.IsAbs) {
				*reinterpret_cast<QWORD*>(holder.textSection()->buffer().data() + LinkLaterOffsets[i]) = GetBaseAddress() + TranslateOldAddress(line.Pointer.Abs - GetBaseAddress());
			} else {
				*reinterpret_cast<DWORD*>(holder.textSection()->buffer().data() + LinkLaterOffsets[i]) = TranslateOldAddress(line.Pointer.RVA);
			}
		} else {
			LOG(Failed, MODULE_REASSEMBLER, "This also should never happen (LinkLater[i].Type != JumpTable && LinkLater[i].Type != Pointer)\n");
			return false;
		}
	}
	for (int i = 0; i < XREFs.Size(); i++) {
		holder.bindLabel(XREFLabels[i], holder.textSection()->id(), TranslateOldAddress(XREFs[i]) - SectionHeaders[0].VirtualAddress);
	}
	LinkLater.Release();
	LinkLaterOffsets.Release();
	XREFs.Release();
	XREFLabels.Release();
	if (a.bFailed) {
		LOG(Failed, MODULE_REASSEMBLER, "Detected assembly errors\n");
		return false;
	}

	// Translate known addresses
	for (int i = 0; i < 16; i++) {
		if (i == 5) continue;
		NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress = TranslateOldAddress(NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress);
		if (NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress == _UI32_MAX) {
			LOG(Warning, MODULE_REASSEMBLER, "Failed to translate data directory %d\n", i);
			NTHeaders.x64.OptionalHeader.DataDirectory[i].VirtualAddress = NTHeaders.x64.OptionalHeader.DataDirectory[i].Size = 0;
		}
	}
	NTHeaders.x64.OptionalHeader.AddressOfEntryPoint = TranslateOldAddress(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint);
	Vector<DWORD> Relocations = GetRelocations();
	for (int i = 0; i < Relocations.Size(); i++) {
		Relocations.Replace(i, TranslateOldAddress(Relocations[i]));
		/*for (int j = 0; j < holder.relocEntries().size(); j++) {
			if (holder.relocEntries().at(j)->relocType() == RelocType::kAbsToAbs) {
				
			} else if (holder.relocEntries().at(j)->relocType() != RelocType::kNone) {
				LOG(Warning, MODULE_REASSEMBLER, "Relocation not handled\n");
			}
		}*/
	}
	Buffer relocs = GenerateRelocSection(Relocations);
	NTHeaders.x64.OptionalHeader.DataDirectory[5].Size = relocs.u64Size;

	// Copy data
	LOG(Info, MODULE_REASSEMBLER, "Finalizing\n");
	holder.flatten();
	holder.relocateToBase(GetBaseAddress() + SectionHeaders[0].VirtualAddress);
	LOG(Info_Extended, MODULE_REASSEMBLER, "Assembled code has %d sections, and has %d relocations\n", holder.sectionCount(), holder.hasRelocEntries() ? holder.relocEntries().size() : 0);
	if (holder.hasUnresolvedLinks()) holder.resolveUnresolvedLinks();
	if (holder.hasUnresolvedLinks()) LOG(Warning, MODULE_REASSEMBLER, "Assembled code has %d unsolved links\n", holder.unresolvedLinkCount());
	if (a.bFailed) {
		LOG(Failed, MODULE_PACKER, "Failed to assemble\n");
		return false;
	}
	for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		SectionData[i].Release();
		Buffer buf = { 0 };
		SectionData.Replace(i, buf);
		if (!Sections[i].NewVirtualSize && !Sections[i].NewRawSize) {
			DeleteSection(i);
			i--;
		}
		buf.u64Size = Sections[i].NewRawSize;
		buf.pBytes = reinterpret_cast<BYTE*>(malloc(buf.u64Size));
		if (holder.textSection()->buffer().size() < Sections[i].NewRVA - SectionHeaders[0].VirtualAddress + buf.u64Size) {
			LOG(Failed, MODULE_REASSEMBLER, "Failed to read assembled code (size: %p, expected: %p)\n", holder.textSection()->buffer().size(), Sections[i].NewRVA - SectionHeaders[0].VirtualAddress + buf.u64Size);
			return false;
		}
		memcpy(buf.pBytes, holder.textSection()->buffer().data() + Sections[i].NewRVA - SectionHeaders[0].VirtualAddress, buf.u64Size);
		SectionData.Replace(i, buf);
		IMAGE_SECTION_HEADER header = SectionHeaders[i];
		header.VirtualAddress = Sections[i].NewRVA;
		header.SizeOfRawData = Sections[i].NewRawSize;
		header.Misc.VirtualSize = Sections[i].NewVirtualSize;
		SectionHeaders.Replace(i, header);
	}
	
	// Insert relocation data
	IMAGE_SECTION_HEADER RelocHeader = { 0 };
	RelocHeader.Misc.VirtualSize = RelocHeader.SizeOfRawData = relocs.u64Size;
	RelocHeader.VirtualAddress = SectionHeaders[SectionHeaders.Size() - 1].VirtualAddress + SectionHeaders[SectionHeaders.Size() - 1].Misc.VirtualSize;
	RelocHeader.VirtualAddress += (RelocHeader.VirtualAddress % NTHeaders.x64.OptionalHeader.SectionAlignment) ? NTHeaders.x64.OptionalHeader.SectionAlignment - (RelocHeader.VirtualAddress % NTHeaders.x64.OptionalHeader.SectionAlignment) : 0;
	NTHeaders.x64.OptionalHeader.DataDirectory[5].VirtualAddress = RelocHeader.VirtualAddress;
	RelocHeader.Characteristics = IMAGE_SCN_MEM_READ;
	memcpy(RelocHeader.Name, ".reloc\0", 8);
	SectionHeaders.Push(RelocHeader);
	SectionData.Push(relocs);
	NTHeaders.x64.FileHeader.NumberOfSections++;

	// Fix exception data
	IMAGE_DATA_DIRECTORY ExcDataDir = NTHeaders.x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = SectionData[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		IMAGE_SECTION_HEADER ExcSecHeader = SectionHeaders[FindSectionByRVA(ExcDataDir.VirtualAddress)];
		if (ExcData.pBytes && ExcSecHeader.VirtualAddress) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - ExcSecHeader.VirtualAddress);
			for (DWORD i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				CheckRuntimeFunction(&pArray[i], true);
			}
		}
	}

	FixHeaders();
	LOG(Success, MODULE_REASSEMBLER, "Finished assembly\n");
	return true;
}

bool Asm::Strip() {
	LOG(Info_Extended, MODULE_REASSEMBLER, "Stripping PE\n");
	// Debug directory
	if (NTHeaders.x64.OptionalHeader.DataDirectory[6].Size && NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress) {
		DWORD dwSize = NTHeaders.x64.OptionalHeader.DataDirectory[6].Size;
		for (int i = 0, n = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY); i < n; i++) {
			IMAGE_DEBUG_DIRECTORY debug = ReadRVA<IMAGE_DEBUG_DIRECTORY>(NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress + sizeof(IMAGE_DEBUG_DIRECTORY) * i);
			RemoveData(debug.AddressOfRawData, debug.SizeOfData);
			dwSize += debug.SizeOfData;
		}
		RemoveData(NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress, NTHeaders.x64.OptionalHeader.DataDirectory[6].Size);
		LOG(Info, MODULE_REASSEMBLER, "Removed debug directory (%#x bytes)\n", dwSize);
		NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress = NTHeaders.x64.OptionalHeader.DataDirectory[6].Size = 0;
	}

	// Symbol table
	if (NTHeaders.x64.FileHeader.PointerToSymbolTable && NTHeaders.x64.FileHeader.PointerToSymbolTable < OverlayOffset) {
		LOG(Warning, MODULE_REASSEMBLER, "Stripping non-overlay symbols, this is untested code!\n");
		// Find debug sections
		IMAGE_SYMBOL sym;
		DWORD rva = RawToRVA(NTHeaders.x64.FileHeader.PointerToSymbolTable);
		DWORD end = rva + sizeof(IMAGE_SYMBOL) * NTHeaders.x64.FileHeader.NumberOfSymbols;
		for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSymbols; i++) {
			ReadRVA(rva + sizeof(IMAGE_SYMBOL) * i, &sym, sizeof(IMAGE_SYMBOL));
			if (!sym.N.Name.Short) {
				char* str = ReadRVAString(rva + sizeof(IMAGE_SYMBOL) * NTHeaders.x64.FileHeader.NumberOfSymbols + sym.N.Name.Long);
				int len = lstrlenA(str);
				end += len;
				if (len > 7) {
					char bak = str[7];
					str[7] = 0;
					if (!lstrcmpA(str, ".debug_")) {
						if (SectionHeaders[sym.SectionNumber - 1].Misc.VirtualSize || SectionHeaders[sym.SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							IMAGE_SECTION_HEADER Header = SectionHeaders[sym.SectionNumber - 1];
							Header.Misc.VirtualSize = 0;
							Header.VirtualAddress = 0;
							SectionHeaders.Replace(sym.SectionNumber - 1, Header);
							LOG(Info, MODULE_REASSEMBLER, "Unloaded section %.8s (%s)\n", SectionHeaders[sym.SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		RemoveData(rva, end - rva);
		LOG(Info, MODULE_REASSEMBLER, "Removed %d symbols\n", NTHeaders.x64.FileHeader.NumberOfSymbols);
	}

	// Overlay
	if (NTHeaders.x64.FileHeader.PointerToSymbolTable >= OverlayOffset) {
		IMAGE_SYMBOL* pSyms = reinterpret_cast<IMAGE_SYMBOL*>(Overlay.pBytes + (NTHeaders.x64.FileHeader.PointerToSymbolTable - OverlayOffset));
		char* pStrs = reinterpret_cast<char*>(pSyms) + sizeof(IMAGE_SYMBOL) * NTHeaders.x64.FileHeader.NumberOfSymbols;
		for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSymbols; i++) {
			if (!pSyms[i].N.Name.Short && pSyms[i].N.Name.Long) {
				char* str = pStrs + pSyms[i].N.Name.Long;
				if (lstrlenA(str) > 7) {
					char bak = str[7];
					str[7] = 0;
					if (!lstrcmpA(str, ".debug_")) {
						if (SectionHeaders[pSyms[i].SectionNumber - 1].Misc.VirtualSize || SectionHeaders[pSyms[i].SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							IMAGE_SECTION_HEADER Header = SectionHeaders[pSyms[i].SectionNumber - 1];
							Header.Misc.VirtualSize = 0;
							Header.VirtualAddress = 0;
							SectionHeaders.Replace(pSyms[i].SectionNumber - 1, Header);
							LOG(Info, MODULE_REASSEMBLER, "Unloaded section %.8s (%s)\n", SectionHeaders[pSyms[i].SectionNumber - 1].Name, str);
						}
					}
					str[7] = bak;
				}
			}
		}
		LOG(Info, MODULE_REASSEMBLER, "Removed %d symbols\n", NTHeaders.x64.FileHeader.NumberOfSymbols);
	}
	DiscardOverlay();

	// Useless sections
	for (WORD i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		if (!SectionHeaders[i].VirtualAddress || !SectionHeaders[i].Misc.VirtualSize) {
			LOG(Info, MODULE_REASSEMBLER, "Removed section %.8s\n", SectionHeaders[i].Name);
			DeleteSection(i);
			i--;
		}
	}
	NTHeaders.x64.FileHeader.PointerToSymbolTable = 0;
	NTHeaders.x64.FileHeader.NumberOfSymbols = 0;
	NTHeaders.x64.FileHeader.Characteristics |= IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_DEBUG_STRIPPED;

	LOG(Success, MODULE_REASSEMBLER, "Stripped\n");
	return true;
}

void Asm::DeleteSection(_In_ WORD wIndex) {
	Sections.Remove(wIndex);
	PE::DeleteSection(wIndex);
}

DWORD Asm::GetAssembledSize(_In_ DWORD SectionIndex) {
	DWORD dwSize = 0;
	Vector<Line>* Lines = Sections[SectionIndex].Lines;
	for (DWORD i = 0; i < Lines->Size(); i++) {
		dwSize += GetLineSize(Lines->At(i));
	}
	return dwSize;
}

void Asm::InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line Line) {
	if (SectionIndex >= Sections.Size() || LineIndex > Sections[SectionIndex].Lines->Size()) return;
	Sections[SectionIndex].Lines->Insert(LineIndex, Line);
}

DWORD Asm::TranslateOldAddress(_In_ DWORD dwRVA) {
	if (dwRVA < NTHeaders.x64.OptionalHeader.SizeOfHeaders) return dwRVA;

	// Check if in between headers
	DWORD SecIndex = 0;
	for (; SecIndex < Sections.Size(); SecIndex++) {
		if (dwRVA < Sections[SecIndex].OldRVA) {
			return (SecIndex ? (dwRVA + Sections[SecIndex - 1].NewRVA) - Sections[SecIndex - 1].OldRVA : dwRVA);
		}
		else if (dwRVA >= Sections[SecIndex].OldRVA && dwRVA < Sections[SecIndex].OldRVA + Sections[SecIndex].OldSize) {
			break;
		}
	}

	DWORD szIndex = FindIndex(SecIndex, dwRVA);
	if (szIndex == _UI32_MAX) {
		LOG(Failed, MODULE_REASSEMBLER, "Failed to translate address %#x\n", dwRVA);
		return 0;
	}
	if (szIndex < Sections[SecIndex].Lines->Size()) {
		return dwRVA + Sections[SecIndex].Lines->At(szIndex).NewRVA - Sections[SecIndex].Lines->At(szIndex).OldRVA;
	}
	
	return dwRVA + Sections[SecIndex].NewRVA - Sections[SecIndex].OldRVA;
}

void Asm::DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex) {
	Sections[SectionIndex].Lines->Remove(LineIndex);
}

void Asm::RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize) {
	DWORD sec = FindSectionIndex(dwRVA);
	DWORD i = FindIndex(sec, dwRVA);
	if (i == _UI32_MAX) {
		LOG(Warning, MODULE_REASSEMBLER, "Failed to remove data at range %#x - %#x\n", dwRVA, dwRVA + dwSize);
		return;
	}

	Line data = Sections[sec].Lines->At(i);
	if (data.Type != Embed || data.OldRVA > dwRVA || data.OldRVA + GetLineSize(data) < dwRVA + dwSize) {
		LOG(Warning, MODULE_REASSEMBLER, "Failed to remove data at range %#x - %#x (this version can be fixed later)\n", dwRVA, dwRVA + dwSize);
		return;
	}

	Line data_new = { 0 };
	data_new.Type = Embed;
	if (data.OldRVA < dwRVA) {
		data_new.OldRVA = data.OldRVA;
		data_new.Embed.Size = dwRVA - data_new.OldRVA;
		InsertLine(sec, i, data_new);
		i++;
	}
	if (data.OldRVA + GetLineSize(data) > dwRVA + dwSize) {
		data_new.OldRVA = dwRVA + dwSize;
		data_new.Embed.Size = data.OldRVA + GetLineSize(data) - (dwRVA + dwSize);
		InsertLine(sec, i, data_new);
		i++;
	}
	DeleteLine(sec, i);
}

Vector<FunctionRange> Asm::GetDisassembledFunctionRanges() {
	Vector<FunctionRange> clone = FunctionRanges;
	//clone.bCannotBeReleased = true;
	return clone;
}

DWORD GetLineSize(_In_ Line& line) {
	switch (line.Type) {
	case Decoded:
		return line.Decoded.Instruction.length;
	case Embed:
		return line.Embed.Size;
	case Padding:
		return line.Padding.Size;
	case JumpTable:
		return sizeof(DWORD);
	case RawInsert:
		return line.RawInsert.u64Size;
	case Pointer:
		return (line.Pointer.IsAbs ? sizeof(uint64_t) : sizeof(DWORD));
	}
	LOG(Failed, MODULE_REASSEMBLER, "Failed to calculate length of instruction (unknown mnemonic)\n");
	return 0;
}

size_t Asm::GetNumLines() {
	size_t ret = 0;
	for (int i = 0; i < Sections.Size(); i++) {
		ret += Sections[i].Lines->nItems;
	}
	return ret;
}

Vector<AsmSection> Asm::GetSections() {
	Vector<AsmSection> clone = Sections;
	//clone.bCannotBeReleased = true;
	return clone;
}

Buffer GenerateRelocSection(Vector<DWORD> Relocations) {
	Buffer ret = { 0 };
	WORD current = 0;
	ret.u64Size = sizeof(IMAGE_BASE_RELOCATION);
	ret.pBytes = reinterpret_cast<BYTE*>(malloc(ret.u64Size));
	IMAGE_BASE_RELOCATION* pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.pBytes);
	pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
	pReloc->VirtualAddress = 0;

	// If nothing needs to be relocated, generate NULL relocation
	if (!Relocations.Size())
		return ret;

	pReloc->VirtualAddress = (Relocations[0] / 0x1000) * 0x1000;
	BYTE RelocOff = 0;
	for (int i = 0; i < Relocations.Size(); i++) {
		current = 0b1010000000000000; // DIR64

		// Generate new rva
		if (pReloc->VirtualAddress + 0x1000 <= Relocations[i]) {
			ret.u64Size += sizeof(IMAGE_BASE_RELOCATION);
			ret.pBytes = reinterpret_cast<BYTE*>(realloc(ret.pBytes, ret.u64Size));
			RelocOff = ret.u64Size - sizeof(IMAGE_BASE_RELOCATION);
			pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.pBytes + RelocOff);
			pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
			pReloc->VirtualAddress = (Relocations[i] / 0x1000) * 0x1000;
		}

		// Add entry
		current |= (Relocations[i] - pReloc->VirtualAddress) & 0b0000111111111111;
		ret.u64Size += sizeof(WORD);
		ret.pBytes = reinterpret_cast<BYTE*>(realloc(ret.pBytes, ret.u64Size));
		pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.pBytes + RelocOff);
		pReloc->SizeOfBlock += sizeof(WORD);
		*reinterpret_cast<WORD*>(ret.pBytes + ret.u64Size - sizeof(WORD)) = current;
	}
	return ret;
}