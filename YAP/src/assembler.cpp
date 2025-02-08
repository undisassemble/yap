#include "assembler.hpp"
#include "asmtranslations.hpp"

// SDK defs
#define YAP_OP_REASM_MUTATION 0b10000000
#define YAP_OP_REASM_SUB      0b00000010

bool bFailed = false;

void AsmJitErrorHandler::handleError(_In_ Error error, _In_ const char* message, _In_ BaseEmitter* emitter) {
	LOG(Failed, MODULE_YAP, "AsmJit error: %s\n", message);
	bFailed = true;
}

bool ProtectedAssembler::FromDis(_In_ Line* pLine, _In_ Label* pLabel) {
	if (!pLine || pLine->Type != Decoded) return false;

	// Special ops
	if (pLine->Decoded.Instruction.mnemonic == ZYDIS_MNEMONIC_NOP && pLine->Decoded.Instruction.operand_count_visible > 0 && pLine->Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && (pLine->Decoded.Operands[0].mem.disp.value & 0xFFFFFF00) == 0x89658000) {
		BYTE op = pLine->Decoded.Operands[0].mem.disp.value & 0xFF;
		if (op & YAP_OP_REASM_MUTATION) {
			bMutate = MutationLevel = op & 0b01111111;
			LOG(Info, MODULE_REASSEMBLER, "Set mutation level to %d (at RVA %#010x)\n", MutationLevel, pLine->OldRVA);
		} else if (op & YAP_OP_REASM_SUB) {
			bSubstitute = op & 1;
			LOG(Info, MODULE_REASSEMBLER, "%s substitution (at RVA %#010x)\n", bSubstitute ? "Enabled" : "Disabled", pLine->OldRVA);
		} else {
			LOG(Warning, MODULE_REASSEMBLER, "Reasm macro noticed, but unable to interpret instruction.\n");
		}
		return true;
	}

	// Mutate
	strict();
	if (!bWaitingOnEmit && !HeldLocks) { stub(); }
	else { bWaitingOnEmit = false; }
	this->bFailed = ::bFailed;

	// Prefixes
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_LOCK) lock();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REP) rep();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPE) repe();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPNE) repne();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPZ) repz();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_REPNZ) repnz();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_XRELEASE) xrelease();
	if (pLine->Decoded.Instruction.attributes & ZYDIS_ATTRIB_HAS_XACQUIRE) xacquire();
	
	// Special instructions
	if (!pLine->Decoded.Instruction.operand_count_visible) {
		switch (pLine->Decoded.Instruction.mnemonic) {
		case ZYDIS_MNEMONIC_MOVSB: return movsb();
		case ZYDIS_MNEMONIC_MOVSW: return movsw();
		case ZYDIS_MNEMONIC_MOVSD: return movsd();
		case ZYDIS_MNEMONIC_MOVSQ: return movsq();
		case ZYDIS_MNEMONIC_STOSB: return stosb();
		case ZYDIS_MNEMONIC_STOSW: return stosw();
		case ZYDIS_MNEMONIC_STOSD: return stosd();
		case ZYDIS_MNEMONIC_STOSQ: return stosq();
		}
	}

	// Convert mnemonic
	InstId mnem = ZydisToAsmJit::Mnemonics[pLine->Decoded.Instruction.mnemonic];
	if (!mnem) {
		char formatted[MAX_PATH];
		ZydisFormatter fmt;
		ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterFormatInstruction(&fmt, &pLine->Decoded.Instruction, pLine->Decoded.Operands, pLine->Decoded.Instruction.operand_count_visible, formatted, sizeof(formatted), pLine->OldRVA, NULL);
		LOG(Failed, MODULE_REASSEMBLER, "Failed to translate mnemonic: %s\n", formatted);
		this->bFailed = true;
		return false;
	}

	// Convert operands
	Operand_ ops[4] = { 0 };
	for (int i = 0; i < pLine->Decoded.Instruction.operand_count_visible && i < 4; i++) {
		Mem memop;
		Imm immop;
		int scale = 0;
		
		switch (pLine->Decoded.Operands[i].type) {
		case ZYDIS_OPERAND_TYPE_IMMEDIATE:
			if (pLabel && pLine->Decoded.Instruction.operand_count_visible == 1) { // Probably jmp or smthn
				ops[0] = *pLabel;
			} else {
				immop = Imm();
				immop._setValueInternal(pLine->Decoded.Operands[i].imm.value.s, ImmType::kInt);
				ops[i] = immop;
			}
			break;
		case ZYDIS_OPERAND_TYPE_REGISTER:
			ops[i] = ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].reg.value];
			break;
		case ZYDIS_OPERAND_TYPE_POINTER:
			memop = Mem(pLine->Decoded.Operands[i].ptr.offset);
			memop.setSegment(ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].ptr.segment]._baseId); // might need to be changed, relies on segment being a zydis encoded register
			memop.setSize(pLine->Decoded.Operands[i].size / 8);
			ops[i] = memop;
			break;
		case ZYDIS_OPERAND_TYPE_MEMORY:
			if (pLine->Decoded.Operands[i].mem.scale == 2) scale = 1;
			else if (pLine->Decoded.Operands[i].mem.scale == 4) scale = 2;
			else if (pLine->Decoded.Operands[i].mem.scale == 8) scale = 3;
			if (pLabel) {
				memop = Mem(*pLabel, ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.index], scale, 0);
			} else {
				memop = Mem(ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.base], ZydisToAsmJit::Registers[pLine->Decoded.Operands[i].mem.index], scale, pLine->Decoded.Operands[i].mem.disp.has_displacement ? (pLine->Decoded.Operands[i].mem.disp.value & 0xFFFFFFFF) : 0);
			}
			if (pLine->Decoded.Operands[i].mem.segment == ZYDIS_REGISTER_GS) memop.setSegment(gs);
			else if (pLine->Decoded.Operands[i].mem.segment == ZYDIS_REGISTER_FS) memop.setSegment(fs);
			memop.setSize(pLine->Decoded.Operands[i].size / 8);
			ops[i] = memop;
		}
	}
	if (pLine->Decoded.Instruction.operand_count_visible > 4) {
		char formatted[MAX_PATH];
		ZydisFormatter fmt;
		ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
		ZydisFormatterFormatInstruction(&fmt, &pLine->Decoded.Instruction, pLine->Decoded.Operands, pLine->Decoded.Instruction.operand_count_visible, formatted, sizeof(formatted), pLine->OldRVA, NULL);
		LOG(Warning, MODULE_REASSEMBLER, "Unable to process all operands: %s\n", formatted);
	}
	
	// Substitution
	if (bSubstitute) {
		switch (mnem) {
		case Inst::kIdRet:
			if (!pLine->Decoded.Instruction.operand_count_visible) return ret();
			break;
		case Inst::kIdMov:
			if (pLine->Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
				Gp o0;
				memcpy(&o0, &ops[0], sizeof(Gp));
				if (pLine->Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					Gp o1;
					memcpy(&o1, &ops[1], sizeof(Gp));
					return mov(o0, o1);
				} else if (pLine->Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
					Imm o1;
					memcpy(&o1, &ops[1], sizeof(Imm));
					return mov(o0, o1);
				} else {
					Mem o1;
					memcpy(&o1, &ops[1], sizeof(Mem));
					return mov(o0, o1);
				}
			} else {
				Mem o0;
				memcpy(&o0, &ops[0], sizeof(Mem));
				if (pLine->Decoded.Operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
					Gp o1;
					memcpy(&o1, &ops[1], sizeof(Gp));
					return mov(o0, o1);
				} else {
					Imm o1;
					memcpy(&o1, &ops[1], sizeof(Imm));
					return mov(o0, o1);
				}
			}
			break;
		case Inst::kIdCall:
			if (pLine->Decoded.Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && pLabel) return call(*pLabel);
			break;
		}
	}
	bStrict = false;
	return !Assembler::_emit(mnem, ops[0], ops[1], ops[2], &ops[3]);
}

int ProtectedAssembler::randstack(_In_ int nMin, _In_ int nMax) {
	if (nMin > nMax) return 0;
	HeldLocks++;
	Gp temp;
	int n = nMin == nMax ? nMin : nMin + (rand() % (nMax - nMin));
	int ret = 0;
	for (int i = 0; i < n; i++) {
		// Select register
		do {
			temp = truerandreg();
		} while (stack.Size() < countof(regs) - Blacklist.Size() && (stack.Includes(temp) || Blacklist.Includes(temp.r64())));
		if (stack.Includes(temp) || Blacklist.Includes(temp.r64())) break;
		push(temp);
		stack.Push(temp);
		ret++;

		// Random push
		if (rand() & 1) {
			for (int j = 0, m = 5; j < m; j++) {
				temp = randreg();
				stack.Push(temp);
				ret++;
				push((rand() & 1) ? 0 : rand());
				break;
			}
		}

		// Random math again
		for (int j = rand() % MutationLevel; j; j--) {
			randinst(randreg());
		}
	}
	HeldLocks--;
	return ret;
}

void ProtectedAssembler::restorestack(_In_ int n) {
	if (!stack.Size()) return;
	HeldLocks++;
	if (n < 0) {
		while (stack.Size()) {
			// Restore register
			pop(stack.Pop());

			for (int j = rand() % MutationLevel; j; j--) {
				randinst(randreg());
			}
		}
		stack.Release();
	} else {
		for (int i = 0; i < n; i++) {
			pop(stack.Pop());

			for (int j = rand() % MutationLevel; j; j--) {
				randinst(randreg());
			}
		}
	}
	HeldLocks--;
}

void ProtectedAssembler::randinst(Gp o0) {
	if (!stack.Includes(o0) || Blacklist.Includes(o0.r64()) || Blacklist.Includes(o0) || o0.size() != 8) return;
	HeldLocks++;
	const BYTE sz = 32;
	const BYTE beg_unsafe = 17;
	BYTE end = (bStrict DEBUG_ONLY(|| Options.Debug.bStrictMutation)) ? beg_unsafe : sz;
	Mem peb = ptr(0x60);
	peb.setSegment(gs);
	switch (rand() % end) {
	case 0:
		lea(o0, ptr(rip, rand()));
		break;
	case 1:
		lea(o0, ptr(truerandreg(), (rand() & 1 ? 1 : -1) * rand()));
		break;
	case 2:
		lea(o0, ptr(truerandreg(), truerandreg(), rand() % 3));
		break;
	case 3:
		lea(o0, ptr(truerandreg(), truerandreg(), rand() % 3, (rand() & 1 ? 1 : -1) * rand()));
		break;
	case 4: {
		BYTE r = 3 + rand() % (MutationLevel * 2);
		Label j2 = newLabel();
		jmp(j2);
		for (; r > 0; r--) db(rand() & 0xFF);
		bind(j2);
		break;
	}
	case 5:
		mov(o0, 0);
		break;
	case 6:
		mov(o0, rand());
		break;
	case 7:
		mov(o0, ptr(rsp, rand() % 32));
		break;
	case 8:
		mov(o0, peb);
		break;
	case 9: {
		BYTE r = 3 + rand() % (MutationLevel * 2);
		Label j2 = newLabel();
		jbe(j2);
		jnc(j2);
		for (; r > 0; r--) db(rand() & 0xFF);
		bind(j2);
		break;
	}
	case 10: { // In IDA these disassemble as the same instruction, but function differently ;)
		if (o0.r64() == rax.r64()) {
			block();
			xchg(eax, eax);
		} else {
			db(0x46);
			db(0x90);
		}
		break;
	}
	case 11: {
		push(truerandreg());
		xchg(o0, ptr(rsp));
		pop(o0);
		break;
	}
	case 12:
		not_(o0);
		break;
	case 13: {
		bool bNeedsValid = false;
		BYTE valid[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x64, 0x65, 0x66, 0x67, 0x2E, 0x3E, 0xF2, 0xF3 };
		for (int i = 0, n = 1 + rand() % 14; i < n; i++) {
			BYTE selected = valid[rand() % sizeof(valid)];
			if (selected == 0x41 || selected == 0x43 || selected == 0x45 || selected == 0x47 || selected == 0x49 || selected == 0x4B || selected == 0x4D) {
				// Try again
				if (i == 13) { i--; continue; }

				// Make room for validating prefix
				if (!bNeedsValid) n--;
				bNeedsValid = true;
			}
			db(selected);
		}
		if (bNeedsValid) {
			BYTE validators[] = { 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E };
			db(validators[rand() % sizeof(validators)]);
		}
		db(0x90);
		break;
	}
	case 14: {
		BYTE valid[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x64, 0x65, 0x66, 0x67, 0x2E, 0x3E, 0xF2, 0xF3 };
		for (int i = 0, n = 1 + rand() % 12; i < n; i++) {
			BYTE selected = valid[rand() % sizeof(valid)];
			db(selected);
		}
		not_(o0);
		break;
	}
	case 15: {
		bool bNeedsValid = false;
		BYTE valid[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x64, 0x65, 0x66, 0x67, 0x2E, 0x3E, 0xF2, 0xF3 };
		for (int i = 0, n = 1 + rand() % 11; i < n; i++) {
			BYTE selected = valid[rand() % sizeof(valid)];
			if (selected == 0x41 || selected == 0x43 || selected == 0x45 || selected == 0x47 || selected == 0x49 || selected == 0x4B || selected == 0x4D) {
				// Try again
				if (i == 10) { i--; continue; }

				// Make room for validating prefix
				if (!bNeedsValid) n--;
				bNeedsValid = true;
			}
			db(selected);
		}
		if (bNeedsValid) {
			BYTE validators[] = { 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E };
			db(validators[rand() % sizeof(validators)]);
		}
		setz(o0.r8());
		break;
	}
	case 16: {
		bool bNeedsValid = false;
		BYTE valid[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x64, 0x65, 0x66, 0x67, 0x2E, 0x3E, 0xF2, 0xF3 };
		for (int i = 0, n = 1 + rand() % 11; i < n; i++) {
			BYTE selected = valid[rand() % sizeof(valid)];
			if (selected == 0x41 || selected == 0x43 || selected == 0x45 || selected == 0x47 || selected == 0x49 || selected == 0x4B || selected == 0x4D) {
				// Try again
				if (i == 10) { i--; continue; }

				// Make room for validating prefix
				if (!bNeedsValid) n--;
				bNeedsValid = true;
			}
			db(selected);
		}
		if (bNeedsValid) {
			BYTE validators[] = { 0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E };
			db(validators[rand() % sizeof(validators)]);
		}
		setnz(o0.r8());
		break;
	}
	
	// Unsafe instructions
	case 17:
		xor_(o0, truerandreg());
		break;
	case 18:
		xor_(o0, rand64() & 0x7FFFFFFF);
		break;
	case 19:
		sub(o0, truerandreg());
		break;
	case 20:
		sub(o0, rand64() & 0x7FFFFFFF);
		break;
	case 21:
		add(o0, truerandreg());
		break;
	case 22:
		add(o0, rand64() & 0x7FFFFFFF);
		break;
	case 23:
		and_(o0, truerandreg());
		break;
	case 24:
		and_(o0, rand64() & 0x7FFFFFFF);
		break;
	case 25:
		or_(o0, truerandreg());
		break;
	case 26:
		or_(o0, rand64() & 0x7FFFFFFF);
		break;
	case 27:
		cmp(o0, truerandreg());
		break;
	case 28:
		cmp(o0, rand64() & 0x7FFFFFFF);
		break;
	case 29:
		test(o0, o0);
		break;
	case 30:
		setz(o0);
		break;
	case 31:
		setnz(o0);
		break;
	}
	HeldLocks--;
}

// Everything in this stub needs to be blocked otherwise it will cause an infinite loop
void ProtectedAssembler::stub() {
	if (!bMutate) return;
	HeldLocks++;
	DEBUG_ONLY(if (Options.Debug.bGenerateMarks) nop());
	if (stack.Size()) {
		LOG(Warning, MODULE_PACKER, "Stub was requested when stack was not empty, ignoring request.\n");
		return;
	}
	randstack(0, MutationLevel);
	for (int i = 0, n = rand() % MutationLevel; i < n; i++) randinst(randreg());
	restorestack();
	DEBUG_ONLY(if (Options.Debug.bGenerateMarks) nop());
	HeldLocks--;
}

size_t ProtectedAssembler::garbage() {
	if (!bMutate) return 0;
	DEBUG_ONLY(if (::Options.Debug.bGenerateMarks) { HeldLocks++;  nop(); xchg(rax, rax); HeldLocks--; });
	Label randlabel;
	randlabel = newLabel();
	Gp reg;
	for (int i = 0, n = (1000 / (17 - MutationLevel)) + rand() % (10000 / (17 - MutationLevel)); i < n; i++) {
	retry:
		switch (rand() % 46) {
		case 0:
			inc(randsize(truerandreg()));
			break;
		case 1:
			dec(randsize(truerandreg()));
			break;
		case 2:
			reg = randsize(truerandreg());
			xchg(reg, randregofsamesize(reg));
			break;
		case 3:
			reg = randsize(truerandreg());
			cmp(reg, randregofsamesize(reg));
			break;
		case 4:
			cmp(randsize(truerandreg()), 0);
			break;
		case 5:
			mov(randsize(truerandreg()), rand());
			break;
		case 6:
			mov(randsize(truerandreg()), 0);
			break;
		case 7:
			reg = randsize(truerandreg());
			mov(reg, randregofsamesize(reg));
			break;
		case 8:
			break;
		case 9:
			break;
		case 10:
			desync();
			break;
		case 11:
			desync_mov(truerandreg().r64());
			break;
		case 12:
			jz(randlabel);
			break;
		case 13:
			jnz(randlabel);
			break;
		case 14:
			shl(truerandreg(), rand() % 64);
			break;
		case 15:
			shr(truerandreg(), rand() % 64);
			break;
		case 16:
			//mov(truerandreg(), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			break;
		case 17:
			//lea((reg = truerandreg()), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			//mov(truerandreg(), ptr(reg));
			break;
		case 18:
			//lea((reg = truerandreg()), ptr(rip, (rand() & 1 ? -1 : 1) * rand()));
			//mov(truerandreg(), ptr(reg, rand()));
			break;
		case 19:
			break;
		case 20:
			break;
		case 21:
			break;
		case 22:
			break;
		case 23:
			break;
		case 24:
			break;
		case 25:
			break;
		case 26:
			reg = randsize(truerandreg());
			test(reg, reg);
			break;
		case 27:
			cmp(randsize(truerandreg()), rand());
			break;
		case 28:
			xor_(randsize(truerandreg()), rand());
			break;
		case 29:
			reg = randsize(truerandreg());
			xor_(reg, randregofsamesize(reg));
			break;
		case 30:
			or_(randsize(truerandreg()), rand());
			break;
		case 31:
			reg = randsize(truerandreg());
			or_(reg, randregofsamesize(reg));
			break;
		case 32:
			not_(randsize(truerandreg()));
			break;
		case 33:
			reg = randsize(truerandreg());
			sub(reg, randregofsamesize(reg));
			break;
		case 34:
			sub(randsize(truerandreg()), rand());
			break;
		case 35:
			reg = randsize(truerandreg());
			add(reg, randregofsamesize(reg));
			break;
		case 36:
			add(randsize(truerandreg()), rand());
			break;
		case 37:
			mul(randsize(truerandreg()));
			break;
		case 38:
			lea(truerandreg(), ptr(truerandreg()));
			break;
		case 39:
			lea(truerandreg(), ptr(truerandreg(), truerandreg()));
			break;
		case 40:
			lea(truerandreg(), ptr(truerandreg(), truerandreg(), rand() % 4, rand()));
			break;
		case 41:
			lea(truerandreg(), ptr(truerandreg(), rand()));
			break;
		default:
			if (!i) goto retry;
			if (!code()->isLabelBound(randlabel)) bind(randlabel);
			randlabel = newLabel();
		}
	}
	DEBUG_ONLY(if (::Options.Debug.bGenerateMarks) { HeldLocks++;  nop(); xchg(rax, rax); HeldLocks--; });
	return 0;
}

void ProtectedAssembler::desync() {
	if (!bMutate || bStrict) return;
	HeldLocks++;
	db(0xEB);
	block();
	inc(eax);
	HeldLocks--;
}

void ProtectedAssembler::desync_jz() {
	if (!bMutate || bStrict) return;
	HeldLocks++;
	db(0x74);
	block();
	inc(ebx);
	HeldLocks--;
}

void ProtectedAssembler::desync_jnz() {
	if (!bMutate || bStrict) return;
	HeldLocks++;
	db(0x75);
	block();
	inc(ebx);
	HeldLocks--;
}

void ProtectedAssembler::desync_mov(Gpq o0) {
	if (!bMutate) return;
	uint64_t dist = 3 + rand() % MutationLevel * 2;
	push((dist << 16) + 0xE940);
	Label after = newLabel();
	lea(o0, ptr(after));
	pop(qword_ptr(o0));
	bind(after);
	for (int i = 0; i < dist + 6; i++) db(rand() & 0xFF);
}

Error ProtectedAssembler::call(Gp o0) {
	if (bWaitingOnEmit || !bMutate) return Assembler::call(o0);
	BYTE dist = 64 + (rand() % 192);
	if (bStrict) dist = 0;
	push(o0);
	push(o0);
	push(o0);
	Label after = newLabel();
	lea(o0, ptr(after));
	if (dist) add(o0, dist);
	mov(ptr(rsp, 0x10), o0);
	pop(o0);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::call(Imm o0) {
	return Assembler::call(o0);
}

Error ProtectedAssembler::call(Label o0) {
	if (bWaitingOnEmit || !bMutate) return Assembler::call(o0);
	Gp reg = truerandreg();
	BYTE dist = 64 + (rand() % 192);
	if (bStrict) dist = 0;
	push(reg);
	push(reg);
	push(reg);
	Label after = newLabel();
	lea(reg, ptr(after));
	if (dist) add(reg, dist);
	mov(ptr(rsp, 0x10), reg);
	lea(reg, ptr(o0));
	mov(ptr(rsp, 0x08), reg);
	pop(reg);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::call(Mem o0) {
	if (bWaitingOnEmit || !bMutate || o0.baseReg() == rsp) return Assembler::call(o0);
	Gp reg = truerandreg();
	o0.setSize(8);
	BYTE dist = 64 + (rand() % 192);
	if (bStrict) dist = 0;
	push(o0);
	push(o0);
	push(reg);
	Label after = newLabel();
	lea(reg, ptr(after));
	if (dist) add(reg, dist);
	mov(ptr(rsp, 0x10), reg);
	pop(reg);
	ret();
	bind(after);
	for (int i = 0; i < dist; i++) {
		BYTE byte = 0;
		do {
			byte = rand() & 0xFF;
		} while (byte == 0xC3 || byte == 0xCB || !byte);
		db(byte);
	}
	return 0;
}

Error ProtectedAssembler::mov(Gp o0, Imm o1) {
	// Cause of zero-extending we can safely turn DWORD registers into QWORD ones
	if (bWaitingOnEmit || !bMutate || o0.size() < 4 || o1.value() > 0x7FFFFFFF) return Assembler::mov(o0, o1);
	bool j = bStrict;
	push(o1);
	bStrict = j;
	return pop(o0.r64());
}

Error ProtectedAssembler::mov(Gp o0, Gp o1) {
	if (o0.r64() == rsp || o1.r64() == rsp || bWaitingOnEmit || !bMutate || o0.size() != o1.size() || o0.size() == 1 || o0.size() == 4) return Assembler::mov(o0, o1);
	bool j = bStrict;
	push(o1);
	bStrict = j;
	return pop(o0);
}

Error ProtectedAssembler::mov(Gp o0, Mem o1) {
	o1.setSize(o0.size());
	if (bWaitingOnEmit || !bMutate || o0.size() == 1 || o0.size() == 4 || o1.baseReg() == rsp) return Assembler::mov(o0, o1);
	bool j = bStrict;
	push(o1);
	bStrict = j;
	return pop(o0);
}

Error ProtectedAssembler::mov(Mem o0, Imm o1) {
	if (bWaitingOnEmit || !bMutate || o0.size() != 8 || o0.baseReg() == rsp) return Assembler::mov(o0, o1);
	bool j = bStrict;
	push(o1);
	bStrict = j;
	return pop(o0);
}

Error ProtectedAssembler::mov(Mem o0, Gp o1) {
	o0.setSize(o1.size());
	if (bWaitingOnEmit || !bMutate || o1.size() == 1 || o1.size() == 4 || o0.baseReg() == rsp) return Assembler::mov(o0, o1);
	bool j = bStrict;
	push(o1);
	bStrict = j;
	return pop(o0);
}

Error ProtectedAssembler::movzx(Gp o0, Mem o1) {
	return Assembler::movzx(o0, o1);
	if (o1.hasBaseReg() && o1.baseReg() == rsp) return Assembler::movzx(o0, o1);
	o0 = o0.r64();
	if (bWaitingOnEmit || !bMutate || o1.size() != 2) return Assembler::movzx(o0, o1);
	push(0);
	pop(o0);
	Gp o16 = o0.r16();
	push(o16);
	push(o16);
	push(o16);
	push(o1);
	return pop(o0);
}

Error ProtectedAssembler::movzx(Gp o0, Gp o1) {
	return Assembler::movzx(o0, o1);
}

uint64_t ProtectedAssembler::GetStackSize() {
	uint64_t ret = 0;
	for (int i = 0, n = stack.Size(); i < n; i++) {
		ret += stack[i].size();
	}
	return ret;
}

Error ProtectedAssembler::ret() {
	if (stack.Size()) restorestack();
	if (bWaitingOnEmit || !bMutate) return Assembler::ret();
	Gp reg = truerandreg();
	bool j = bStrict;
	push(reg);
	bStrict = j;
	mov(reg, qword_ptr(0x7FFE02F8));
	bStrict = j;
	xchg(qword_ptr(rsp), reg);
	bStrict = j;
	pop(qword_ptr(rip));
	return dq(rand64());
}

// I doubt I will ever use this one
Error ProtectedAssembler::ret(Imm o0) {
	if (stack.Size()) restorestack();
	return Assembler::ret(o0);
}

// Emitter hook
Error ProtectedAssembler::_emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) {
	if (!bWaitingOnEmit && !HeldLocks) { stub(); bStrict = false; }
	else { bWaitingOnEmit = false; }
	this->bFailed = ::bFailed;
	return Assembler::_emit(instId, o0, o1, o2, opExt);
}