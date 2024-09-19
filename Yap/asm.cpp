#include "asm.hpp"

typedef struct {
	BYTE Version_Flag;
	BYTE PrologSize;
	BYTE CntUnwindCodes;
	BYTE FrReg : 4;
	BYTE FrRegOff : 4;
} UNWIND_INFO_HDR;

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

bool IsInstructionCF(_In_ ZydisDecodedInstruction* pInstruction) {
	switch (pInstruction->mnemonic) {
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
	return IsInstructionCF(pInstruction) || pOperand->type == ZYDIS_OPERAND_TYPE_MEMORY;
}

Asm::Asm() : PE(false) {}

Asm::Asm(_In_ char* sFileName) : PE(sFileName) {
	ZydisDecoderInit(&Decoder, GetMachine(), ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.OldRVA = GetSectionHeader(i)->VirtualAddress;
		sec.OldSize = GetSectionHeader(i)->Misc.VirtualSize;
		Sections.Push(sec);
	}
}

Asm::Asm(_In_ HANDLE hFile) : PE(hFile) {
	ZydisDecoderInit(&Decoder, GetMachine(), ZYDIS_STACK_WIDTH_64);
	Vector<Line> lines;
	lines.bExponentialGrowth = true;
	AsmSection sec = { 0 };
	for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSections; i++) {
		sec.Lines = reinterpret_cast<Vector<Line>*>(malloc(sizeof(Vector<Line>)));
		memcpy(sec.Lines, &lines, sizeof(Vector<Line>));
		sec.NewRVA = sec.OldRVA = GetSectionHeader(i)->VirtualAddress;
		sec.OldSize = GetSectionHeader(i)->Misc.VirtualSize;
		Sections.Push(sec);
	}
}

Asm::~Asm() {
	for (int i = 0; i < Sections.Size(); i++) {
		Sections.At(i).Lines->Release();
		free(Sections.At(i).Lines);
	}
	Sections.Release();
	JumpTables.Release();
}

DWORD Asm::FindSectionIndex(_In_ DWORD dwRVA) {
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	for (DWORD i = 0; i < Sections.Size(); i++) {
		if (Sections.At(i).OldRVA <= dwRVA && Sections.At(i).OldRVA + Sections.At(i).OldSize >= dwRVA) {
			DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
			return i;
		}
	}
	DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
	return _UI32_MAX;
}

DWORD Asm::FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	if (dwSec > Sections.Size()) return _UI32_MAX;
	Vector<Line>* Lines = Sections.At(dwSec).Lines;

	// If no lines exist, it will just be the first line
	if (!Lines || !Lines->Size())
		return _UI32_MAX;

	// Check bounds
	if (dwRVA >= Lines->At(0).OldRVA && dwRVA < Lines->At(0).OldRVA + GetLineSize(Lines->At(0)))
		return 0;
	if (dwRVA >= Lines->At(Lines->Size() - 1).OldRVA && dwRVA < Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size() - 1;

	if (Lines->Size() == 1)
		return _UI32_MAX;

	// Search
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	while (szMin < szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		if (szMin + 1 == szMax) {
			i = szMin = szMax;
		}

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
	}

	DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
	return _UI32_MAX;
}

DWORD Asm::FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA) {
	Vector<Line>* Lines = Sections.At(dwSec).Lines;

	// If no lines exist, it will just be the first line
	if (!Lines->Size())
		return 0;

	// Check bounds
	if (dwRVA < Lines->At(0).OldRVA)
		return 0;
	else if (dwRVA == Lines->At(0).OldRVA)
		return _UI32_MAX - 1;
	if (dwRVA >= Lines->At(Lines->Size() - 1).OldRVA + GetLineSize(Lines->At(Lines->Size() - 1)))
		return Lines->Size();
	else if (dwRVA == Lines->At(Lines->Size() - 1).OldRVA)
		return _UI32_MAX - 1;

	// Search
	DEBUG_ONLY(uint64_t TickCount = GetTickCount64());
	size_t szMin = 0, szMax = Lines->Size(), i = 0;
	while (szMin < szMax) {
		i = szMin + (szMax - szMin) * 0.5;

		if (dwRVA >= Lines->At(i).OldRVA + GetLineSize(Lines->At(i))) {
			// In between
			if (dwRVA < Lines->At(i + 1).OldRVA) {
				DEBUG_ONLY(Data.TimeSpentSearching += GetTickCount64() - TickCount);
				return i + 1;
			}

			// Shift range
			szMin = i;
		}

		else if (dwRVA < Lines->At(i).OldRVA) {
			// In between
			if (dwRVA > Lines->At(i - 1).OldRVA + GetLineSize(Lines->At(i - 1))) {
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
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
	Vector<Line>* Lines;
	Vector<Line> TempLines;
	DWORD SectionIndex;
	char FormattedBuf[128];
	ZydisFormatter Formatter;
	ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);

	do {
		// Setup
		dwRVA = ToDisasm.Pop();
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
		Lines = Sections.At(SectionIndex).Lines;
		Buffer RawBytes = { 0 };
		{
			RawBytes = GetSectionBytes(FindSectionByRVA(dwRVA));
			IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRVA(dwRVA));
			if (!pHeader || !RawBytes.pBytes || !RawBytes.u64Size) {
				LOG(Warning, MODULE_REASSEMBLER, "Failed to get bytes for RVA %lu\n", dwRVA);
				continue;
			}
			RawBytes.pBytes += dwRVA - pHeader->VirtualAddress;
			RawBytes.u64Size -= dwRVA - pHeader->VirtualAddress;
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
					trva = odisp + rva;
					if (!(trva != 0xCCCCCCCC && trva >= Sections.At(SectionIndex).OldRVA && trva < Sections.At(SectionIndex).OldRVA + Sections.At(SectionIndex).OldSize)) break;
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
					if (i != _UI32_MAX - 1) Sections.At(SecIndex).Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				} while (1);
			}
			if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_MOV && CraftedLine.Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && CraftedLine.Decoded.Operands[1].mem.scale == 4 && CraftedLine.Decoded.Operands[1].mem.base != ZYDIS_REGISTER_RIP) {
				DWORD rva = 0;
				DWORD disp = CraftedLine.Decoded.Operands[1].mem.disp.value;
				while ((rva = ReadRVA<DWORD>(disp)) != 0xCCCCCCCC && rva >= Sections.At(SectionIndex).OldRVA && rva < Sections.At(SectionIndex).OldRVA + Sections.At(SectionIndex).OldSize) {
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
					if (i != _UI32_MAX - 1) Sections.At(SecIndex).Lines->Insert(i, TempJumpTable);
					disp += sizeof(DWORD);
				}
			}
 
			if (IsInstructionCF(&CraftedLine.Decoded.Instruction)) {
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
						IMAGE_DATA_DIRECTORY ImportDir = Decoder.machine_mode == ZYDIS_MACHINE_MODE_LONG_64 ? GetNtHeaders()->x64.OptionalHeader.DataDirectory[1] : GetNtHeaders()->x86.OptionalHeader.DataDirectory[1];
						if (u64Referencing >= ImportDir.VirtualAddress && u64Referencing < (uint64_t)ImportDir.VirtualAddress + ImportDir.Size) {
							u64Referencing = 0;
						}

						// Find the section (u64Referencing is absolute, not an RVA, so we have to translate it manually)
						else {
							WORD wContainingIndex = FindSectionByRVA(u64Referencing);
							IMAGE_SECTION_HEADER* pContainingHeader = GetSectionHeader(wContainingIndex);
							if (!pContainingHeader || wContainingIndex == _UI16_MAX) {
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
									Sections.At(wContainingIndex).Lines->Insert(wInsertAt, insert);
								}
							}

							u64Referencing -= GetBaseAddress();
						}
					}

					if (u64Referencing) {
						// Disassemble the address (if good)
						IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRVA(u64Referencing));
						if (pHeader && pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE && pHeader->SizeOfRawData > u64Referencing - pHeader->VirtualAddress) {
							if (!ToDisasm.Includes(u64Referencing)) ToDisasm.Push(u64Referencing);
						}

						// Exit if unconditional
						if (CraftedLine.Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_JMP) {
							break;
						}
					}
				}
			}

			// Adjust vars
			dwRVA += CraftedLine.Decoded.Instruction.length;
			RawBytes.u64Size -= CraftedLine.Decoded.Instruction.length;
			RawBytes.pBytes += CraftedLine.Decoded.Instruction.length;

			// Stop disassembly if the next instruction has already been disassembled
			if (i < Lines->Size() && Lines->At(i).OldRVA == dwRVA) {
				break;
			}
		}

		// Insert lines
		Lines->Insert(i, TempLines);
	} while (ToDisasm.Size());
	return true;
}

bool Asm::CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr) {
	// Fix addresses mode
	if (bFixAddr) {
		pFunc->BeginAddress = TranslateOldAddress(pFunc->BeginAddress);
		pFunc->EndAddress = TranslateOldAddress(pFunc->EndAddress);
	} else {
		// Disassemble
		if (pFunc->BeginAddress && !DisasmRecursive(pFunc->BeginAddress))
			return false;
	}

	// Check unwind info for function
	UNWIND_INFO_HDR UnwindInfo = ReadRVA<UNWIND_INFO_HDR>(pFunc->UnwindData);

	// EHANDLER flag being set means that at the end is a RUNTIME_FUNCTION struct
	if (UnwindInfo.Version_Flag == 0x21) {
		RUNTIME_FUNCTION F2 = ReadRVA<RUNTIME_FUNCTION>(pFunc->UnwindData + sizeof(UNWIND_INFO_HDR) + UnwindInfo.CntUnwindCodes * 2);
		// Unwind info addr + sizeof(UNWIND_INFO_HDR) + Num UNWIND_CODE * sizeof(UNWIND_CODE) = address of RUNTIME_FUNCTION
		if (!CheckRuntimeFunction(&F2, bFixAddr))
			return false;
		if (bFixAddr) {
			DWORD oOff = pFunc->UnwindData;
			pFunc->UnwindData = TranslateOldAddress(pFunc->UnwindData);
			WriteRVA<RUNTIME_FUNCTION>(oOff + sizeof(UNWIND_INFO_HDR) + UnwindInfo.CntUnwindCodes * 2, F2);
		}
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
		insert.OldRVA = relocs.At(i);
		insert.Type = Pointer;
		insert.Pointer.IsAbs = true;
		insert.Pointer.Abs = ReadRVA<uint64_t>(insert.OldRVA);
		WORD wContainingSec = FindSectionIndex(insert.OldRVA);
		WORD wIndex = FindPosition(wContainingSec, insert.OldRVA);
		if (wIndex == _UI16_MAX || wContainingSec == _UI16_MAX) {
			LOG(Warning, MODULE_REASSEMBLER, "Failed to find position to insert line at 0x%p\n", GetBaseAddress() + insert.OldRVA);
			continue;
		}
		Sections.At(wContainingSec).Lines->Insert(wIndex, insert);
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
				Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD) * 3;
				insert.Pointer.RVA = entry.NameRVA;
				Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
				insert.Pointer.RVA = entry.ThunkRVA;
				Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
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
					Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
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
			Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNames;
			Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
			wIndex++;
			insert.OldRVA += sizeof(DWORD);
			insert.Pointer.RVA = ExportTable.AddressOfNameOrdinals;
			Sections.At(wSecIndex).Lines->Insert(wIndex, insert);

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
				Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
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
				Sections.At(wSecIndex).Lines->Insert(wIndex, insert);
				wIndex++;
				insert.OldRVA += sizeof(DWORD);
			}
		}
	}

	// Initialize Zydis
	ZydisDecoderInit(&Decoder, GetMachine(), x86 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);

	// Disassemble entry point
	if (!DisasmRecursive(GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint)) {
		return false;
	}
	LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled Entry Point (0x%p)\n", GetBaseAddress() + GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint);

	// Error check (TEMPORARY)
	{
		Vector<Line>* Lines = Sections.At(FindSectionIndex(GetNtHeaders()->x64.OptionalHeader.AddressOfEntryPoint)).Lines;
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
			if (!DisasmRecursive(Exports.At(i))) {
				return false;
			}
			LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled exported function \'%s\'\n", ExportNames.At(i));
		}
	}
	LOG(Info_Extended, MODULE_REASSEMBLER, "Disassembled Exports\n");

	// Disassemble exception dir
	IMAGE_DATA_DIRECTORY ExcDataDir = GetNtHeaders()->x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = GetSectionBytes(FindSectionByRVA(ExcDataDir.VirtualAddress));
		IMAGE_SECTION_HEADER* pExcSecHeader = GetSectionHeader(FindSectionByRVA(ExcDataDir.VirtualAddress));
		if (ExcData.pBytes && pExcSecHeader) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - pExcSecHeader->VirtualAddress);
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
	LOG(Success, MODULE_REASSEMBLER, "Finished disassembly\n");

	// Insert missing data + padding
	DEBUG_ONLY(uint64_t OldTimeSpentSeaching = Data.TimeSpentSearching);
	DEBUG_ONLY(TickCount = GetTickCount64());
	Line line;
	LOG(Info_Extended, MODULE_REASSEMBLER, "Filling gaps\n");
	for (int i = 0; i < Sections.Size(); i++) {
		LOG(Info_Extended, MODULE_REASSEMBLER, "Filling section %.8s (%llu lines)\n", GetSectionHeader(i)->Name, Sections.At(i).Lines->Size());

		// Incase section holds no lines
		if (!Sections.At(i).Lines->Size()) {	
			line.Type = Embed;
			line.OldRVA = Sections.At(i).OldRVA;
			if (Sections.At(i).OldSize < GetSectionHeader(i)->SizeOfRawData) {
				line.Embed.Size = Sections.At(i).OldSize;
				Sections.At(i).Lines->Push(line);
				continue;
			}
			line.Embed.Size = GetSectionHeader(i)->SizeOfRawData;
			if (line.OldRVA && line.Embed.Size) Sections.At(i).Lines->Push(line);
			line.Type = Padding;
			line.OldRVA += line.Embed.Size;
			line.Padding.Size = Sections.At(i).OldSize - (line.OldRVA - Sections.At(i).OldRVA);
			if (line.OldRVA && line.Padding.Size) Sections.At(i).Lines->Push(line);
			continue;
		}

		// Insert prepended data
		line.Type = Embed;
		if (Sections.At(i).Lines->At(0).OldRVA > Sections.At(i).OldRVA) {
			line.OldRVA = Sections.At(i).OldRVA;
			line.Embed.Size = Sections.At(i).Lines->At(0).OldRVA - Sections.At(i).OldRVA;
			Sections.At(i).Lines->Insert(0, line);
		} else if (Sections.At(i).Lines->At(0).OldRVA < Sections.At(i).OldRVA) {
			LOG(Warning, MODULE_REASSEMBLER, "First line in section %d begins below the section (you should *hopefully* never see this)\n", i);
		}

		// Insert embedded data
		for (int j = 0; j < Sections.At(i).Lines->Size() - 1; j++) {
			line.OldRVA = Sections.At(i).Lines->At(j).OldRVA + GetLineSize(Sections.At(i).Lines->At(j));
			if (line.OldRVA < Sections.At(i).Lines->At(j + 1).OldRVA) {
				line.Embed.Size = Sections.At(i).Lines->At(j + 1).OldRVA - line.OldRVA;
				Sections.At(i).Lines->Insert(j + 1, line);
				j++;
			}
		}

		// Insert ending data
		line.OldRVA = Sections.At(i).Lines->At(Sections.At(i).Lines->Size() - 1).OldRVA + GetLineSize(Sections.At(i).Lines->At(Sections.At(i).Lines->Size() - 1));
		if (line.OldRVA - Sections.At(i).OldRVA < GetSectionHeader(i)->SizeOfRawData && line.OldRVA - Sections.At(i).OldRVA < Sections.At(i).OldSize) {
			line.Embed.Size = ((Sections.At(i).OldSize < GetSectionHeader(i)->SizeOfRawData) ? Sections.At(i).OldSize : GetSectionHeader(i)->SizeOfRawData) - (line.OldRVA - Sections.At(i).OldRVA);
			Sections.At(i).Lines->Push(line);
		}

		// Insert padding
		line.Type = Padding;
		line.OldRVA = Sections.At(i).Lines->At(Sections.At(i).Lines->Size() - 1).OldRVA + GetLineSize(Sections.At(i).Lines->At(Sections.At(i).Lines->Size() - 1));
		line.Padding.Size = Sections.At(i).OldSize - (line.OldRVA - Sections.At(i).OldRVA);
		if (line.OldRVA && line.Padding.Size) Sections.At(i).Lines->Push(line);
	}
	LOG(Success, MODULE_REASSEMBLER, "Filled gaps\n");
	DEBUG_ONLY(Data.TimeSpentFilling = GetTickCount64() - TickCount - (Data.TimeSpentSearching - OldTimeSpentSeaching));

	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent inserting: %llu\n", Data.TimeSpentInserting));
	DEBUG_ONLY(LOG(Info_Extended, MODULE_REASSEMBLER, "Time spent filling gaps: %llu\n", Data.TimeSpentFilling));
	LOG(Success, MODULE_REASSEMBLER, "Finished disassembly\n");
	return true;
}

bool Asm::FixAddresses() {
	LOG(Info, MODULE_REASSEMBLER, "Patching instructions\n");
	Vector<Line>* Lines;
	
	// Fix sections
	AsmSection sec;
	sec = Sections.At(0);
	sec.NewRVA = sec.OldRVA;
	sec.NewSize = GetAssembledSize(0);
	Sections.Replace(0, sec);
	if (sec.NewRVA != sec.OldRVA || sec.NewSize != sec.OldSize) LOG(Info_Extended, MODULE_REASSEMBLER, "%.8s changed memory range: (%08x - %08x) -> (%08x - %08x)\n", GetSectionHeader((WORD)0)->Name, sec.OldRVA, sec.OldRVA + sec.OldSize, sec.NewRVA, sec.NewRVA + sec.NewSize);
	for (WORD SecIndex = 1; SecIndex < Sections.Size(); SecIndex++) {
		sec = Sections.At(SecIndex);
		sec.NewRVA = Sections.At(SecIndex - 1).NewRVA + Sections.At(SecIndex - 1).NewSize;
		sec.NewRVA += (sec.NewRVA % NTHeaders.x64.OptionalHeader.SectionAlignment) ? NTHeaders.x64.OptionalHeader.SectionAlignment - (sec.NewRVA % NTHeaders.x64.OptionalHeader.SectionAlignment) : 0;
		sec.NewSize = GetAssembledSize(SecIndex);
		Sections.Replace(SecIndex, sec);
		if (sec.NewRVA != sec.OldRVA || sec.NewSize != sec.OldSize) LOG(Info_Extended, MODULE_REASSEMBLER, "%.8s changed memory range: (%08x - %08x) -> (%08x - %08x)\n", GetSectionHeader(SecIndex)->Name, sec.OldRVA, sec.OldRVA + sec.OldSize, sec.NewRVA, sec.NewRVA + sec.NewSize);
	}

	// Set new RVAs
	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Apply new addresses
		Lines = Sections.At(SecIndex).Lines;
		DWORD dwCurrentAddress = Sections.At(SecIndex).NewRVA;
		Line line = { 0 };
		for (size_t i = 0; i < Lines->Size(); i++) {
			line = Lines->At(i);
			line.NewRVA = dwCurrentAddress;
			if (line.OldRVA == NTHeaders.x64.OptionalHeader.AddressOfEntryPoint) {
				NTHeaders.x64.OptionalHeader.AddressOfEntryPoint = line.NewRVA;
			}
			Lines->Replace(i, line);

			// Update address
			dwCurrentAddress += GetLineSize(line);
		}
	}

	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		// Fix relative addresses in asm
		Lines = Sections.At(SecIndex).Lines;
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
						if (IsInstructionCF(&line.Decoded.Instruction) && line.Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
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

						if (u64Referencing < Sections.At(0).OldRVA) {
							ZydisFormatter fmt;
							ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
							char op[128];
							ZydisFormatterFormatOperand(&fmt, &line.Decoded.Instruction, &line.Decoded.Operands[j], op, 128, GetBaseAddress() + line.OldRVA, NULL);
							LOG(Warning, MODULE_REASSEMBLER, "Failed to translate address at %p (%s)\n", GetBaseAddress() + line.OldRVA, op);
							continue;
						}

						_SecIndex = FindSectionIndex(u64Referencing);
						_LineIndex = FindIndex(_SecIndex, u64Referencing);
						if (_LineIndex == _UI32_MAX) {
							LOG(Failed, MODULE_REASSEMBLER, "Failed to find location of RVA %#x\n", u64Referencing);
							return false;
						}
						
						// Calc offset
						i64Off = Sections.At(_SecIndex).Lines->At(_LineIndex).NewRVA - Sections.At(_SecIndex).Lines->At(_LineIndex).OldRVA;
						if (line.Decoded.Operands[j].mem.base == ZYDIS_REGISTER_RIP) i64Off -= (line.NewRVA - line.OldRVA);

						// Apply offset
						if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
							line.Decoded.Operands[j].imm.value.s += i64Off;
						} else if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY) {
							line.Decoded.Operands[j].mem.disp.value += i64Off;
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
	IMAGE_DATA_DIRECTORY ExcDataDir = GetNtHeaders()->x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = GetSectionBytes(FindSectionByRVA(ExcDataDir.VirtualAddress));
		IMAGE_SECTION_HEADER* pExcSecHeader = GetSectionHeader(FindSectionByRVA(ExcDataDir.VirtualAddress));
		if (ExcData.pBytes && pExcSecHeader) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - pExcSecHeader->VirtualAddress);
			for (DWORD i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				CheckRuntimeFunction(&pArray[i], true);
			}
		}
	}

	// Fix relocations
	Vector<DWORD> Relocations = GetRelocations();
	for (int i = 0; i < Relocations.Size(); i++) {
		Relocations.Replace(i, TranslateOldAddress(Relocations.At(i)));
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

	LOG(Success, MODULE_REASSEMBLER, "Patched instructions\n");
	return true;
}

bool Asm::Assemble() {
	// Setup
	LOG(Info, MODULE_REASSEMBLER, "Beginning assembly\n");
	if (!Sections.Size()) return false;
	ZydisEncoderRequest Request;
	ZyanStatus Status;
	Vector<Line>* Lines;
	Line line;
	ZyanUSize Size;
	BYTE Raw[ZYDIS_MAX_INSTRUCTION_LENGTH];

	for (DWORD SecIndex = 0; SecIndex < Sections.Size(); SecIndex++) {
		Lines = Sections.At(SecIndex).Lines;

		for (size_t i = 0; i < Lines->Size(); i++) {
			line = Lines->At(i);
			if (line.Type != Decoded) continue;

			// Translate to encoder request
			if (ZYAN_FAILED(Status = ZydisEncoderDecodedInstructionToEncoderRequest(&line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, &Request))) {
				LOG(Failed, MODULE_REASSEMBLER, "Assembler failed at translation (%s)\n", ZydisErrorToString(Status));
				return false;
			}
			
			// Encode the actual instruction
			Size = ZYDIS_MAX_INSTRUCTION_LENGTH;
			if (ZYAN_FAILED(Status = ZydisEncoderEncodeInstruction(&Request, Raw, &Size))) {
				LOG(Failed, MODULE_REASSEMBLER, "Assembler failed to encode instruction at %p (%s)\n", GetBaseAddress() + line.OldRVA, ZydisErrorToString(Status));
				return false;
			}

			// Encoded instruction was larger than the original instruction, this may get fixed later
			if (line.Decoded.Instruction.length < Size) {
				LOG(Failed, MODULE_REASSEMBLER, "Assembler output was too large\n");
				return false;
			}

			// If the assembled size is less than the original, some modifications need to be made
			if (Size < line.Decoded.Instruction.length) {
				// Change immediate values if the instruction changes control flow
				bool bCheckImm = IsInstructionCF(&line.Decoded.Instruction);

				// If there are any memory operations, change the relative offset
				bool bReencode = false;
				for (int j = 0; j < line.Decoded.Instruction.operand_count_visible; j++) {
					if (line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_MEMORY && line.Decoded.Operands[j].mem.disp.value && (line.Decoded.Operands[j].mem.base == ZYDIS_REGISTER_RIP || line.Decoded.Operands[j].mem.base == ZYDIS_REGISTER_EIP)) {
						line.Decoded.Operands[j].mem.disp.value += line.Decoded.Instruction.length - Size;
						bReencode = true;
					}

					else if (bCheckImm && line.Decoded.Operands[j].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
						line.Decoded.Operands[j].imm.value.s += line.Decoded.Instruction.length - Size;
						bReencode = true;
					}
				}

				// Translate
				if (bReencode) {
					if (ZYAN_FAILED(Status = ZydisEncoderDecodedInstructionToEncoderRequest(&line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, &Request))) {
						LOG(Failed, MODULE_REASSEMBLER, "Assembler failed at translation (%s)\n", ZydisErrorToString(Status));
						LOG(Info_Extended, MODULE_REASSEMBLER, "At line %zu\n", i + 1);
						LOG(Info_Extended, MODULE_REASSEMBLER, "Due to resized instruction\n");
						return false;
					}

					// Re-encode
					Size = ZYDIS_MAX_INSTRUCTION_LENGTH;
					if (ZYAN_FAILED(Status = ZydisEncoderEncodeInstruction(&Request, Raw, &Size))) {
						LOG(Failed, MODULE_REASSEMBLER, "Assembler failed at encoding (%s)\n", ZydisErrorToString(Status));
						LOG(Info_Extended, MODULE_REASSEMBLER, "At line %zu\n", i + 1);
						return false;
					}
				}

				// Add NOPs
				ZydisEncoderNopFill(&Raw[Size], line.Decoded.Instruction.length - Size);
				Size = line.Decoded.Instruction.length;
			}

			// Replace
			line.Type = Encoded;
			line.Encoded.Size = Size;
			memcpy(line.Encoded.Raw, Raw, Size);
			Lines->Replace(i, line);
		}

		// Finally, construct the output buffer
		Buffer Buf = { 0 };
		IMAGE_SECTION_HEADER* pCurrentSection = NULL;
		for (size_t i = 0; i < Lines->Size(); i++) {
			if (Lines->At(i).Type == Padding) {
				if (i < Lines->Size() - 1) {
					LOG(Failed, MODULE_REASSEMBLER, "Encountered code beyond the end of the section.\n");
					LOG(Info_Extended, MODULE_REASSEMBLER, "In section %.8s\n", GetSectionHeader(i)->Name);
					return false;
				}
				AsmSection sec = Sections.At(SecIndex);
				sec.NewSize += Lines->At(i).Padding.Size;
				Sections.Replace(SecIndex, sec);
				continue;
			}

			// Insert data
			if (Lines->At(i).Type != RawInsert) {
				Buf.u64Size += GetLineSize(Lines->At(i));
				Buf.pBytes = reinterpret_cast<BYTE*>(realloc(Buf.pBytes, Buf.u64Size));
			}
			switch (Lines->At(i).Type) {
			case Encoded:
				memcpy(Buf.pBytes + Buf.u64Size - Lines->At(i).Encoded.Size, Lines->At(i).Encoded.Raw, Lines->At(i).Encoded.Size);
				break;
			case Embed:
				ReadRVA(Lines->At(i).OldRVA, Buf.pBytes + Buf.u64Size - Lines->At(i).Embed.Size, Lines->At(i).Embed.Size);
				break;
			case JumpTable:
				memcpy(Buf.pBytes + Buf.u64Size - sizeof(DWORD), &line.JumpTable.Value, sizeof(DWORD));
				break;
			case RawInsert:
				Buf.Merge(line.RawInsert);
				break;
			case Pointer:
				if (Lines->At(i).Pointer.IsAbs) {
					*reinterpret_cast<uint64_t*>(Buf.pBytes + Buf.u64Size - sizeof(uint64_t)) = Lines->At(i).Pointer.Abs;
				} else {
					*reinterpret_cast<DWORD*>(Buf.pBytes + Buf.u64Size - sizeof(DWORD)) = Lines->At(i).Pointer.RVA;
				}
				break;
			default:
				LOG(Warning, MODULE_REASSEMBLER, "No data inserted at %#x!\n", Lines->At(i).NewRVA);
			}
		}

#ifdef _DEBUG
		if (Options.Debug.bDumpSections) {
			char sname[12] = { 0 };
			snprintf(sname, 12, "%.8s.bin", GetSectionHeader(SecIndex)->Name);
			HANDLE hFile = CreateFile(sname, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			WriteFile(hFile, Buf.pBytes, Buf.u64Size, NULL, NULL);
			CloseHandle(hFile);
		}
#endif

		AsmSection sec = Sections.At(SecIndex);
		sec.Assembled = Buf;
		Sections.Replace(SecIndex, sec);
	}

	for (int i = 0; i < Sections.Size(); i++) {
		OverwriteSection(i, Sections.At(i).Assembled.pBytes, Sections.At(i).Assembled.u64Size);
		GetSectionHeader(i)->VirtualAddress = Sections.At(i).NewRVA;
		GetSectionHeader(i)->Misc.VirtualSize = Sections.At(i).NewSize;
	}

	FixHeaders();
	LOG(Success, MODULE_REASSEMBLER, "Finished assembly\n");
	return true;
}

bool Asm::Strip() {
	LOG(Info_Extended, MODULE_REASSEMBLER, "Stripping PE\n");
	// Debug directory
	if (NTHeaders.x64.OptionalHeader.DataDirectory[6].Size && NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress) {
		IMAGE_DEBUG_DIRECTORY debug = ReadRVA<IMAGE_DEBUG_DIRECTORY>(NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress);
		RemoveData(debug.AddressOfRawData, debug.SizeOfData);
		RemoveData(NTHeaders.x64.OptionalHeader.DataDirectory[6].VirtualAddress, NTHeaders.x64.OptionalHeader.DataDirectory[6].Size);
		LOG(Info, MODULE_REASSEMBLER, "Removed debug directory (%#x bytes)\n", debug.SizeOfData + NTHeaders.x64.OptionalHeader.DataDirectory[6].Size);
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
						if (pSectionHeaders[sym.SectionNumber - 1].Misc.VirtualSize || pSectionHeaders[sym.SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							LOG(Info, MODULE_REASSEMBLER, "Unloaded section %.8s (%s)\n", pSectionHeaders[sym.SectionNumber - 1].Name, str);
							pSectionHeaders[sym.SectionNumber - 1].Misc.VirtualSize = 0;
							pSectionHeaders[sym.SectionNumber - 1].VirtualAddress = 0;
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
		IMAGE_SYMBOL* pSyms = reinterpret_cast<IMAGE_SYMBOL*>(GetOverlay()->pBytes + (NTHeaders.x64.FileHeader.PointerToSymbolTable - OverlayOffset));
		char* pStrs = reinterpret_cast<char*>(pSyms) + sizeof(IMAGE_SYMBOL) * NTHeaders.x64.FileHeader.NumberOfSymbols;
		for (int i = 0; i < NTHeaders.x64.FileHeader.NumberOfSymbols; i++) {
			if (!pSyms[i].N.Name.Short && pSyms[i].N.Name.Long) {
				char* str = pStrs + pSyms[i].N.Name.Long;
				if (lstrlenA(str) > 7) {
					char bak = str[7];
					str[7] = 0;
					if (!lstrcmpA(str, ".debug_")) {
						if (pSectionHeaders[pSyms[i].SectionNumber - 1].Misc.VirtualSize || pSectionHeaders[pSyms[i].SectionNumber - 1].VirtualAddress) {
							str[7] = bak;
							LOG(Info, MODULE_REASSEMBLER, "Unloaded section %.8s (%s)\n", pSectionHeaders[pSyms[i].SectionNumber - 1].Name, str);
							pSectionHeaders[pSyms[i].SectionNumber - 1].Misc.VirtualSize = 0;
							pSectionHeaders[pSyms[i].SectionNumber - 1].VirtualAddress = 0;
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
		if (!pSectionHeaders[i].VirtualAddress || !pSectionHeaders[i].Misc.VirtualSize) {
			LOG(Info, MODULE_REASSEMBLER, "Removed section %.8s\n", pSectionHeaders[i].Name);
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
	Vector<Line>* Lines = Sections.At(SectionIndex).Lines;
	for (DWORD i = 0; i < Lines->Size(); i++) {
		dwSize += GetLineSize(Lines->At(i));
	}
	return dwSize;
}

void Asm::InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line Line) {
	if (SectionIndex >= Sections.Size() || LineIndex > Sections.At(SectionIndex).Lines->Size()) return;
	Sections.At(SectionIndex).Lines->Insert(LineIndex, Line);
}

DWORD Asm::TranslateOldAddress(_In_ DWORD dwRVA) {
	if (dwRVA < NTHeaders.x64.OptionalHeader.SizeOfHeaders) return dwRVA;

	// Check if in between headers
	DWORD SecIndex = 0;
	for (; SecIndex < Sections.Size(); SecIndex++) {
		if (dwRVA < Sections.At(SecIndex).OldRVA) {
			return (SecIndex ? (dwRVA + Sections.At(SecIndex - 1).NewRVA) - Sections.At(SecIndex - 1).OldRVA : dwRVA);
		}
		else if (dwRVA >= Sections.At(SecIndex).OldRVA && dwRVA < Sections.At(SecIndex).OldRVA + Sections.At(SecIndex).OldSize) {
			break;
		}
	}

	DWORD szIndex = FindIndex(SecIndex, dwRVA);
	if (szIndex == _UI32_MAX) {
		LOG(Failed, MODULE_REASSEMBLER, "Failed to translate address %#x\n", dwRVA);
		return 0;
	}
	if (szIndex < Sections.At(SecIndex).Lines->Size()) {
		return dwRVA + Sections.At(SecIndex).Lines->At(szIndex).NewRVA - Sections.At(SecIndex).Lines->At(szIndex).OldRVA;
	}
	
	return dwRVA + Sections.At(SecIndex).NewRVA - Sections.At(SecIndex).OldRVA;
}

bool Asm::InsertNewLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ ZydisEncoderRequest* pRequest) {
	if (!pRequest || SectionIndex >= Sections.Size() || LineIndex > Sections.At(SectionIndex).Lines->Size()) return false;
	pRequest->machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
	Line line = { 0 };
	line.Type = Encoded;
	ZyanUSize sz = ZYDIS_MAX_INSTRUCTION_LENGTH;
	ZyanStatus status = ZydisEncoderEncodeInstruction(pRequest, line.Encoded.Raw, &sz);
	if (ZYAN_SUCCESS(status)) {
		line.Encoded.Size = sz;
		Sections.At(SectionIndex).Lines->Insert(LineIndex, line);
		return true;
	} else {
		LOG(Failed, MODULE_REASSEMBLER, "Failed to assemble line: %s\n", ZydisErrorToString(status));
		return false;
	}
}

void Asm::DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex) {
	Sections.At(SectionIndex).Lines->Remove(LineIndex);
}

void Asm::RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize) {
	DWORD sec = FindSectionIndex(dwRVA);
	DWORD i = FindIndex(sec, dwRVA);
	if (i == _UI32_MAX) {
		LOG(Warning, MODULE_REASSEMBLER, "Failed to remove data at range %#x - %#x\n", dwRVA, dwRVA + dwSize);
		return;
	}

	Line data = Sections.At(sec).Lines->At(i);
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

Vector<Function> Asm::FindFunctionsRecursive(_In_ DWORD dwRVA) {
	Vector<DWORD> ToDisasm;
	Vector<Function> ret;
	do {
		uint64_t Me = GetBaseAddress() + dwRVA;

		// Check if already disassembled
		if (Processed.Includes(dwRVA)) {
			return ret;
		}
		Processed.Push(dwRVA);

		// Get section bytes
		Buffer Bytes = GetSectionBytes(FindSectionByRVA(dwRVA));
		if (!Bytes.pBytes || !Bytes.u64Size) return ret;
		DWORD dwSecVA = GetSectionHeader(FindSectionByRVA(dwRVA))->VirtualAddress;

		// Disassemble
		ZydisDecodedInstruction Instruction;
		ZydisDecodedOperand Operands[10];
		Function Func;
		while (dwRVA - dwSecVA < Bytes.u64Size && ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder, Bytes.pBytes + dwRVA - dwSecVA, Bytes.u64Size + dwRVA - dwSecVA, &Instruction, Operands))) {
			// If function entry is immediate jump just act like were cool or smthn idk
			if (Instruction.mnemonic == ZYDIS_MNEMONIC_JMP && Me == GetBaseAddress() + dwRVA) {
				ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], Me, &Me);
				if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || Operands[0].type == ZYDIS_OPERAND_TYPE_POINTER) {
					Me = ReadRVA<uint64_t>(Me - GetBaseAddress());
				}
				ToDisasm.Push(Me);
				break;
			}
			
			// Find function bounds
			if (Instruction.mnemonic == ZYDIS_MNEMONIC_CALL && Instruction.operand_count_visible && (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || Operands[0].type == ZYDIS_OPERAND_TYPE_POINTER || Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)) {
				ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], GetBaseAddress() + dwRVA, &Func.u64Address);
				if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY || Operands[0].type == ZYDIS_OPERAND_TYPE_POINTER) {
					Func.u64Address = ReadRVA<uint64_t>(Func.u64Address - GetBaseAddress());
				}
				ToDisasm.Push(Func.u64Address - GetBaseAddress());
			} else if (Instruction.mnemonic == ZYDIS_MNEMONIC_RET) {
				// Index function
				Func.u64Address = Me;
				ret.Push(Func);
				break;
			}

			// Handle jmp, call, etc
			if (Instruction.mnemonic != ZYDIS_MNEMONIC_CALL && IsInstructionCF(&Instruction)) {
				uint64_t Address = 0;
				if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Operands[0], GetBaseAddress() + dwRVA, &Address))) {
					ToDisasm.Push(Address - GetBaseAddress());
				} else {
					LOG(Warning, MODULE_VM, "Failed to determine function at %lu\n", dwRVA);
				}
			}

			// Prepare for next instruction
			dwRVA += Instruction.length;
		}
		
		// Setup for next thingy doodle i cant take this shit no more man im doing this at night on a 4 hour flight man shit this is just a fix because i was getting stack overflows doing recursive shit
		dwRVA = ToDisasm.Pop();
	} while (ToDisasm.Size());

	return ret;
}

Vector<Function> Asm::_CheckRuntimeFunction2(_In_ RUNTIME_FUNCTION* pFunc) {
	uint64_t func = 0;
	Vector<Function> ret;

	// Disassemble
	func = pFunc->BeginAddress;
	ret = FindFunctionsRecursive(func);

skip:
	// Check unwind info for function
	UNWIND_INFO_HDR UnwindInfo = ReadRVA<UNWIND_INFO_HDR>(pFunc->UnwindData);

	// EHANDLER flag being set means that at the end is a RUNTIME_FUNCTION struct
	if (UnwindInfo.Version_Flag == 0x21) {
		RUNTIME_FUNCTION F2 = ReadRVA<RUNTIME_FUNCTION>(pFunc->UnwindData + sizeof(UNWIND_INFO_HDR) + UnwindInfo.CntUnwindCodes * 2);
		// Unwind info addr + sizeof(UNWIND_INFO_HDR) + Num UNWIND_CODE * sizeof(UNWIND_CODE) = address of RUNTIME_FUNCTION
		ret.Merge(_CheckRuntimeFunction2(&F2));
	}
	return ret;
}

Vector<Function> Asm::FindFunctions() {
	// Ensure loaded
	Vector<Function> ret;
	if (Status) return ret;

	// Search entry point
	ret = FindFunctionsRecursive(NTHeaders.x64.OptionalHeader.AddressOfEntryPoint);

	// Search TLS callbacks
	uint64_t* pCallbacks = GetTLSCallbacks();
	if (pCallbacks) {
		for (int i = 0; pCallbacks[i]; i++) {
			ret.Merge(FindFunctionsRecursive(pCallbacks[i] - GetBaseAddress()));
		}
	}

	// Disassemble exception dir
	IMAGE_DATA_DIRECTORY ExcDataDir = GetNtHeaders()->x64.OptionalHeader.DataDirectory[3];
	if (ExcDataDir.VirtualAddress) {
		Buffer ExcData = GetSectionBytes(FindSectionByRVA(ExcDataDir.VirtualAddress));
		IMAGE_SECTION_HEADER* pExcSecHeader = GetSectionHeader(FindSectionByRVA(ExcDataDir.VirtualAddress));
		if (ExcData.pBytes && pExcSecHeader) {
			RUNTIME_FUNCTION* pArray = reinterpret_cast<RUNTIME_FUNCTION*>(ExcData.pBytes + ExcDataDir.VirtualAddress - pExcSecHeader->VirtualAddress);
			for (uint32_t i = 0, n = ExcDataDir.Size / sizeof(RUNTIME_FUNCTION); i < n; i++) {
				ret.Merge(_CheckRuntimeFunction2(&pArray[i]));
			}
		}
	}
	
	// Disassemble exports
	Vector<DWORD> Exports = GetExportedFunctionRVAs();
	for (int i = 0, n = Exports.Size(); i < n; i++) {
		ret.Merge(FindFunctionsRecursive(Exports.At(i)));
	}

	// Remove duplicates
	for (int i = 0, n = ret.Size(); i < n; i++) {
		if (ret.At(i).u64Address < GetBaseAddress()) {
			Function temp = ret.At(i);
			temp.u64Address += GetBaseAddress();
			ret.Replace(i, temp);
		}

		for (int j = i + 1; j < n; j++) {
			if (ret.At(j).u64Address < GetBaseAddress()) {
				Function temp = ret.At(j);
				temp.u64Address += GetBaseAddress();
				ret.Replace(j, temp);
			}

			if (ret.At(i).u64Address == ret.At(j).u64Address) {
				ret.Remove(j);
				n--;
				j--;
			}
		}
	}

	// Apply names
	Vector<char*> Names = GetExportedFunctionNames();
	uint64_t u64Entry = GetBaseAddress() + NTHeaders.x64.OptionalHeader.AddressOfEntryPoint;
	Function current;
	int iNamed = 0;
	for (int i = 0, n = ret.Size(); i < n; i++) {
		current = ret.At(i);
		current.pName = NULL;
		if (current.u64Address == u64Entry) {
			current.pName = "Entry";
		}
		for (int j = 0, m = Names.Size(); j < m; j++) {
			if (current.u64Address == GetBaseAddress() + Exports.At(j)) {
				current.pName = Names.At(j);
				break;
			}
		}
		if (current.pName && i > iNamed) {
			Function temp = ret.At(iNamed);
			ret.Replace(iNamed, current);
			ret.Replace(i, temp);
			iNamed++;
		} else {
			ret.Replace(i, current);
		}
	}

	// Sort
	bool bSorted = false;
	do {
		bSorted = true;
		for (int i = 0, n = ret.Size(); i < n - 1; i++) {
			// Sort by name
			if (ret.At(i).pName) {
				if (ret.At(i + 1).pName && strcmp(ret.At(i).pName, ret.At(i + 1).pName) > 0) {
					bSorted = false;
					Function temp = ret.At(i);
					ret.Replace(i, ret.At(i + 1));
					ret.Replace(i + 1, temp);
				}
				continue;
			}

			// Sort by address
			if (ret.At(i).u64Address > ret.At(i + 1).u64Address) {
				bSorted = false;
				Function temp = ret.At(i);
				ret.Replace(i, ret.At(i + 1));
				ret.Replace(i + 1, temp);
			}
		}
	} while (!bSorted);

	// Remove (some) functions that are too small
	/*uint64_t u64Above = ret.At(ret.Size() - 1).u64Address;
	for (int i = ret.Size() - 1; i > 2; i--) {
		if (ret.At(i - 1).u64Address + VMMinimumSize > u64Above) {
			ret.Remove(i - 1);
		} else {
			u64Above = ret.At(i - 1).u64Address;
		}
	}
	DWORD dwLastRVA = ret.At(ret.Size() - 1).u64Address - GetBaseAddress();
	IMAGE_SECTION_HEADER* pHeader = GetSectionHeader(FindSectionByRVA(dwLastRVA));
	if (pHeader && dwLastRVA + VMMinimumSize > pHeader->VirtualAddress + pHeader->SizeOfRawData) {
		ret.Pop();
	}*/

	Processed.Release();
	Names.Release();
	Exports.Release();
	return ret;
}

DWORD GetLineSize(_In_ Line line) {
	switch (line.Type) {
	case Decoded:
		return line.Decoded.Instruction.length;
	case Encoded:
		return line.Encoded.Size;
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
	return 0;
}

size_t Asm::GetNumLines() {
	size_t ret = 0;
	for (int i = 0; i < Sections.Size(); i++) {
		ret += Sections.At(i).Lines->nItems;
	}
	return ret;
}

Vector<AsmSection> Asm::GetSections() {
	return Sections;
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

	pReloc->VirtualAddress = (Relocations.At(0) / 0x1000) * 0x1000;
	BYTE RelocOff = 0;
	for (int i = 0; i < Relocations.Size(); i++) {
		current = 0b1010000000000000; // DIR64

		// Generate new rva
		if (pReloc->VirtualAddress + 0x1000 <= Relocations.At(i)) {
			ret.u64Size += sizeof(IMAGE_BASE_RELOCATION);
			ret.pBytes = reinterpret_cast<BYTE*>(realloc(ret.pBytes, ret.u64Size));
			RelocOff = ret.u64Size - sizeof(IMAGE_BASE_RELOCATION);
			pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.pBytes + RelocOff);
			pReloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
			pReloc->VirtualAddress = (Relocations.At(i) / 0x1000) * 0x1000;
		}

		// Add entry
		current |= (Relocations.At(i) - pReloc->VirtualAddress) & 0b0000111111111111;
		ret.u64Size += sizeof(WORD);
		ret.pBytes = reinterpret_cast<BYTE*>(realloc(ret.pBytes, ret.u64Size));
		pReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(ret.pBytes + RelocOff);
		pReloc->SizeOfBlock += sizeof(WORD);
		*reinterpret_cast<WORD*>(ret.pBytes + ret.u64Size - sizeof(WORD)) = current;
	}
	return ret;
}