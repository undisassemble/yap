/*!
 * @file assembler.cpp
 * @author undisassemble
 * @brief Obfuscating assembler functions
 * @version 0.0.0
 * @date 2025-09-30
 * @copyright MIT License
 */

#include "assembler.hpp"
#include "util.hpp"

// SDK defs
#define YAP_OP_REASM_MUTATION 0b10000000
#define YAP_OP_REASM_SUB      0b00000010

bool bFailed = false;

void AsmJitErrorHandler::handleError(_In_ Error error, _In_ const char* message, _In_ BaseEmitter* emitter) {
	LOG(Failed, MODULE_YAP, "AsmJit error: %s\n", message);
	bFailed = true;
}

bool ProtectedAssembler::resolve(_In_ Mem o0) {
	// Check compatibility
	if ((o0.hasBaseLabel() && !code()->isLabelBound(o0.baseId()) && !bAdvancedResolve) ||
		(o0.hasBaseReg() && o0.baseReg().isGpd() && child_cast<Gpd>(o0.baseReg()) == esp) ||
		(o0.hasIndexReg() && (o0.indexReg().isRip() || (!o0.indexReg().isGpq() && !o0.indexReg().isGpd()))) ||
		(o0.hasBaseReg() && (o0.baseReg().isRip() || (!o0.baseReg().isGpq() && !o0.baseReg().isGpd()) || (o0.baseReg().isGpd() && child_cast<Gpd>(o0.baseReg()) == esp))) ||
		(o0.hasBaseReg() && !o0.hasIndexReg() && !o0.hasOffset())) {
		return false;
	}

	bool fq = bStrict || bForceStrict;
	Gp reg;
	do {
		reg = truerandreg();
	} while ((o0.hasBaseReg() && reg == o0.baseReg()) || (o0.hasIndexReg() && reg == o0.indexReg()));
	if (fq) {
		pushfq();
	}
	push(reg);
	mov(reg, 0);
	uint64_t off = 0;
	if (o0.hasIndexReg()) {
		if (o0.indexReg().isGpd()) {
			mov(reg.r32(), child_cast<Gpd>(o0.indexReg()));
			if (child_cast<Gpd>(o0.indexReg()) == esp) {
				add(reg, fq ? 16 : 8);
			}
		} else if (o0.indexReg().isGpq()) {
			mov(reg, child_cast<Gpq>(o0.indexReg()));
			if (child_cast<Gpq>(o0.indexReg()) == rsp) {
				add(reg, fq ? 16 : 8);
			}
		}
	}
	if (o0.hasShift() && o0.shift() > 0) {
		shl(reg, o0.shift());
	}
	if (o0.hasBaseLabel()) {
		if (rand() & 1) {
			push(reg);
			lea(reg, ptr(rip));
			off = offset();
			add(ptr(rsp), reg);
			pop(reg);
		} else {
			db(0xE8);
			dd(0x00);
			off = offset();
			add(ptr(rsp), reg);
			pop(reg);
		}
		if (code()->isLabelBound(o0.baseId())) {
			add(reg, code()->labelOffset(o0.baseId()) - off);
		} else {
			NeededLink link = { 0 };
			push(reg);
			mov(reg, 0xFF00FF00FF00FF00);
			link.offsetToLink = offset() - 8;
			link.offsetOfRIP = off;
			link.id = o0.baseId();
			NeededLinks.Push(link);
			add(ptr(rsp), reg);
			pop(reg);
		}
	} else if (o0.hasBaseReg()) {
		if (o0.baseReg().isGpd()) {
			push(child_cast<Gpq>(o0.baseReg()));
			xchg(child_cast<Gpd>(o0.baseReg()), child_cast<Gpd>(o0.baseReg()));
			add(reg, child_cast<Gpq>(o0.baseReg()));
			pop(child_cast<Gpq>(o0.baseReg()));
		} else {
			add(reg, child_cast<Gpq>(o0.baseReg()));
			if (child_cast<Gpq>(o0.baseReg()) == rsp) {
				add(reg, fq ? 16 : 8);
			}
		}
	}
	if (o0.hasOffset()) {
		add(reg, o0.offset());
	}

	if (fq) {
		xchg(reg, ptr(rsp, 8));
		xchg(reg, ptr(rsp));
		popfq();
	} else {
		xchg(reg, ptr(rsp));
	}
	return true;
}

void ProtectedAssembler::resolvelinks() {
	LOG(Info, MODULE_PACKER, "Resolving %d links\n", NeededLinks.Size());
	NeededLink link = { 0 };
	while (NeededLinks.Size()) {
		link = NeededLinks.Pop();
		if (!code()->isLabelBound(link.id)) {
			LOG(Failed, MODULE_PACKER, "Link ID invalid\n");
			bFailed = true;
			return;
		}
		*reinterpret_cast<QWORD*>(code()->textSection()->data() + link.offsetToLink) = code()->labelOffset(link.id) - link.offsetOfRIP;
	}
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
			temp = randreg();
			if (temp.r64() != rsp && temp.size() == 8) {
				stack.Push(temp);
				ret++;
				push((rand() & 1) ? 0 : rand());
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
	if (!stack.Includes(o0) || Blacklist.Includes(o0.r64()) || o0.size() != 8 || o0 == rsp) return;
	HeldLocks++;
	const BYTE sz = 32;
	const BYTE beg_unsafe = 17;
	BYTE end = (bStrict || bForceStrict DEBUG_ONLY(|| Options.Debug.bStrictMutation)) ? beg_unsafe : sz;
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
	if (!bMutate || bStrict || bForceStrict) return;
	HeldLocks++;
	db(0xEB);
	block();
	inc(eax);
	HeldLocks--;
}

void ProtectedAssembler::desync_jz() {
	if (!bMutate || bStrict || bForceStrict) return;
	HeldLocks++;
	db(0x74);
	block();
	inc(ebx);
	HeldLocks--;
}

void ProtectedAssembler::desync_jnz() {
	if (!bMutate || bStrict || bForceStrict) return;
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

uint64_t ProtectedAssembler::GetStackSize() {
	uint64_t ret = 0;
	for (int i = 0, n = stack.Size(); i < n; i++) {
		ret += stack[i].size();
	}
	return ret;
}

// Emitter hook
Error ProtectedAssembler::_emit(InstId instId, const Operand_& o0, const Operand_& o1, const Operand_& o2, const Operand_* opExt) {
	// Special ops
	if (Options.Reassembly.bEnabled && instId == Inst::kIdNop && o0.isMem() && reinterpret_cast<const Mem*>(&o0)->hasOffset() && (reinterpret_cast<const Mem*>(&o0)->offset() & 0xFFFFFF00) == 0x89658000) {
		BYTE op = reinterpret_cast<const Mem*>(&o0)->offset() & 0xFF;
		if (op & YAP_OP_REASM_MUTATION) {
			bMutate = (MutationLevel = op & 0b01111111);
			LOG(Info, MODULE_REASSEMBLER, "Set mutation level to %d\n", MutationLevel);
		} else if (op & YAP_OP_REASM_SUB) {
			bSubstitute = op & 1;
			LOG(Info, MODULE_REASSEMBLER, "%s substitution\n", bSubstitute ? "Enabled" : "Disabled");
		} else {
			LOG(Warning, MODULE_REASSEMBLER, "Reasm macro noticed, but unable to interpret instruction.\n");
		}
		return ErrorCode::kErrorOk;
	}

	// Check prefixes
	InstOptions OldPrefixes = _instOptions;
	_instOptions = InstOptions::kNone;

	// Mutate
	bool bSubFailed = false;
	if (!bWaitingOnEmit && !(uint32_t)(OldPrefixes & (InstOptions::kX86_Lock | InstOptions::kX86_Rep | InstOptions::kX86_Repne | InstOptions::kX86_XAcquire | InstOptions::kX86_XRelease))) {
		bool bOldForce = bForceStrict;
		bForceStrict |= bStrict;
		if (!HeldLocks && bMutate) stub();
		
		// Substitution
		if (bSubstitute) {
			bSubstitute = false;
			#include "modules/substitution.inc"
			bSubstitute = true;
		} else {
			bSubFailed = true;
		}
		
		bForceStrict = bOldForce;
		this->bFailed = ::bFailed;
	} else {
		bSubFailed = true;
	}

	// Emit
	_instOptions = OldPrefixes;
	bStrict = bWaitingOnEmit = false;
	return bSubFailed ? Assembler::_emit(instId, o0, o1, o2, opExt) : ErrorCode::kErrorOk;
}