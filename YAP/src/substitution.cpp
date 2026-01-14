/*!
 * @file substitution.cpp
 * @author undisassemble
 * @brief Reassembler instruction substitution related functions
 * @version 0.0.0
 * @date 2026-01-14
 * @copyright MIT License
 */

#include "util.hpp"
#include "substitution.hpp"

Vector<std::pair<DWORD, SubstitutionCallback_t>> SubstitutionDict;

DWORD MakeSubstitutionID(Inst::Id mnemonic, OperandType o0, OperandType o1, OperandType o2, OperandType o3) {
    return (DWORD)mnemonic | ((DWORD)o0 << 11) | ((DWORD)o1 << 14) | ((DWORD)o2 << 17) | ((DWORD)o3 << 20);
}

void AddSubstitute(SubstitutionCallback_t callback, DWORD SubstitutionID) {
    // Overwrite existing substitution
    for (int i = 0; i < SubstitutionDict.Size(); i++) {
        if (SubstitutionDict[i].first == SubstitutionID) {
            SubstitutionDict[i].second = callback;
            LOG(Warning, MODULE_REASSEMBLER, "Substitution %llu overwritten\n", SubstitutionID);
            return;
        }
    }

    SubstitutionDict.Push(std::make_pair(SubstitutionID, callback));
}

void AddSubstitute(SubstitutionCallback_t callback, Inst::Id mnemonic, OperandType o0, OperandType o1, OperandType o2, OperandType o3) {
    LOG(Info, MODULE_REASSEMBLER, "Registered substitute for %u %u, %u, %u, %u\n", mnemonic, o0, o1, o2, o3);
    AddSubstitute(callback, MakeSubstitutionID(mnemonic, o0, o1, o2, o3));
}

namespace Defaults {
    bool __stdcall lea(ProtectedAssembler* pAsm, const Gp& o0, const Mem& o1, const Operand_&, const Operand_&) {
        if (!o0.isGpq() || !pAsm->resolve(o1)) return false;
        pAsm->pop(o0);
        return true;
    }

    bool __stdcall call(ProtectedAssembler* pAsm, const Gp& o0, const Operand_&, const Operand_&, const Operand_&) {
        Label call_reg_after = pAsm->newLabel();
        BYTE dist = 0;
	    if (!pAsm->is_strict()) {
	    	dist = 64 + (rand() % 192);
        }
	    pAsm->push(o0);
	    pAsm->push(o0);
	    pAsm->push(o0);
	    pAsm->lea(o0, ptr(call_reg_after));
	    if (dist) {
	    	pAsm->add(o0, dist);
        }
	    pAsm->mov(ptr(rsp, 0x10), o0);
	    pAsm->pop(o0);
	    pAsm->ret();
	    pAsm->bind(call_reg_after);
	    for (int i = 0; i < dist; i++) {
	        BYTE byte = 0;
	        do {
	            byte = rand() & 0xFF;
	        } while (byte == 0xC3 || byte == 0xCB || !byte);
	        pAsm->db(byte);
	    }
        return true;
    }

    bool __stdcall call(ProtectedAssembler* pAsm, const Label& o0, const Operand_&, const Operand_&, const Operand_&) {
        Label call_label_after = pAsm->newLabel();
        Gp reg = pAsm->truerandreg();
	    BYTE dist = 0;
	    if (!pAsm->is_strict()) {
	    	dist = 64 + (rand() % 192);
        }
	    pAsm->push(reg);
	    pAsm->push(reg);
	    pAsm->push(reg);
	    pAsm->lea(reg, ptr(call_label_after));
	    if (dist) {
	    	pAsm->add(reg, dist);
        }
	    pAsm->mov(ptr(rsp, 0x10), reg);
	    pAsm->lea(reg, ptr(o0));
	    pAsm->mov(ptr(rsp, 0x08), reg);
	    pAsm->pop(reg);
	    pAsm->ret();
	    pAsm->bind(call_label_after);
	    for (int i = 0; i < dist; i++) {
	        BYTE byte = 0;
	        do {
	            byte = rand() & 0xFF;
	        } while (byte == 0xC3 || byte == 0xCB || !byte);
	        pAsm->db(byte);
	    }
        return true;
    }

    bool __stdcall call(ProtectedAssembler* pAsm, const Mem& o0, const Operand_&, const Operand_&, const Operand_&) {
        if (o0.baseReg() == rsp) return false;
        Label call_mem_after = pAsm->newLabel();
        Gp reg = pAsm->truerandreg();
        Mem _o0 = o0;
        _o0.setSize(8);
	    BYTE dist = 0;
	    if (!pAsm->is_strict()) {
	    	dist = 64 + (rand() % 192);
        }
	    if (pAsm->resolve(_o0)) {
	    	pAsm->xchg(reg, ptr(rsp));
	    	pAsm->mov(reg, ptr(reg));
	    	pAsm->xchg(reg, ptr(rsp));
	    	pAsm->push(qword_ptr(rsp));
        } else {
	    	pAsm->push(_o0);
	    	pAsm->push(_o0);
        }
	    pAsm->push(reg);
	    pAsm->lea(reg, ptr(call_mem_after));
	    if (dist) {
	    	pAsm->add(reg, dist);
        }
	    pAsm->mov(ptr(rsp, 0x10), reg);
	    pAsm->pop(reg);
	    pAsm->ret();
	    pAsm->bind(call_mem_after);
	    for (int i = 0; i < dist; i++) {
	        BYTE byte = 0;
	        do {
	            byte = rand() & 0xFF;
	        } while (byte == 0xC3 || byte == 0xCB || !byte);
	        pAsm->db(byte);
	    }
        return true;
    }

    bool __stdcall mov(ProtectedAssembler* pAsm, const Gp& o0, const Imm& o1, const Operand_&, const Operand_&) {
        if (o0.size() < 4 || o1.value() > 0x7FFFFFFF) return false;
        pAsm->push(o1);
        pAsm->pop(o0.r64());
        return true;
    }

    bool __stdcall mov(ProtectedAssembler* pAsm, const Gp& o0, const Gp& o1, const Operand_&, const Operand_&) {
        if (o1.r64() == rsp || o0.size() != o1.size() || o0.size() == 1 || o0.size() == 4) return false;
        pAsm->push(o1);
        pAsm->pop(o0);
        return true;
    }

    bool __stdcall mov(ProtectedAssembler* pAsm, const Gp& o0, const Mem& o1, const Operand_&, const Operand_&) {
        if (o1.baseReg() == rsp || o0.size() == 1 || o0.size() == 4) return false;
        Mem _o1 = o1;
	    _o1.setSize(o0.size());
	    pAsm->push(_o1);
	    pAsm->pop(o0);
        return true;
    }

    bool __stdcall mov(ProtectedAssembler* pAsm, const Mem& o0, const Imm& o1, const Operand_&, const Operand_&) {
        if (o0.size() != 8 || o1.value() > 0x7FFFFFFF) return false;
        if (pAsm->resolve(o0)) {
	    	Gp reg = pAsm->truerandreg();
	    	pAsm->push(o1);
	    	pAsm->xchg(reg, ptr(rsp, 8));
	    	pAsm->pop(qword_ptr(reg));
	    	pAsm->pop(reg);
        } else {
	    	pAsm->push(o1);
	    	pAsm->pop(o0);
        }
        return true;
    }

    bool __stdcall mov(ProtectedAssembler* pAsm, const Mem& o0, const Gp& o1, const Operand_&, const Operand_&) {
        if (o1.size() == 1 || o1.size() == 4) return false;
        Mem _o0 = o0;
	    _o0.setSize(o1.size());
	    if (pAsm->resolve(_o0)) {
	    	Gp reg;
	    	do {
	    	    reg = pAsm->truerandreg();
	    	} while (reg == o1.r64());
	    	pAsm->push(o1);
	    	if (o1.size() == 8) {
	    		pAsm->xchg(reg, ptr(rsp, 8));
	    		pAsm->pop(qword_ptr(reg));
            } else {
	    		pAsm->xchg(reg, ptr(rsp, 2));
	    		pAsm->pop(word_ptr(reg));
            }
	    	pAsm->pop(reg);
        } else {
	    	pAsm->push(o1);
	    	pAsm->pop(_o0);
        }
        return true;
    }

    bool __stdcall jmp(ProtectedAssembler* pAsm, const Gp& o0, const Operand_&, const Operand_&, const Operand_&) {
        if (o0.size() != 8) return false;
        pAsm->push(o0);
        pAsm->ret();
        return true;
    }

    bool __stdcall jmp(ProtectedAssembler* pAsm, const Label& o0, const Operand_&, const Operand_&, const Operand_&) {
        Gp reg = pAsm->truerandreg();
	    pAsm->push(reg);
	    pAsm->lea(reg, ptr(o0));
	    pAsm->xchg(reg, ptr(rsp));
	    pAsm->ret();
        return true;
    }

    bool __stdcall jmp(ProtectedAssembler* pAsm, const Mem& o0, const Operand_&, const Operand_&, const Operand_&) {
        if (pAsm->resolve(o0)) {
	    	Gp reg = pAsm->truerandreg();
	    	pAsm->xchg(ptr(rsp), reg);
	    	pAsm->mov(reg, ptr(reg));
	    	pAsm->xchg(ptr(rsp), reg);
        } else {
	    	pAsm->push(o0);
        }
	    pAsm->ret();
        return true;
    }
    
    bool __stdcall ret(ProtectedAssembler* pAsm, const Operand_&, const Operand_&, const Operand_&, const Operand_&) {
        Gp reg = pAsm->truerandreg();
	    pAsm->push(reg);
	    pAsm->mov(reg, qword_ptr(0x7FFE02F8));
	    pAsm->xchg(qword_ptr(rsp), reg);
	    pAsm->pop(qword_ptr(rip));
	    pAsm->dq(rand64());
        return true;
    }
};

void RegisterDefaultSubstitutions() {
    AddSubstitute<Gp, Mem>(Defaults::lea, Inst::kIdLea);
    AddSubstitute<Gp>(Defaults::call, Inst::kIdCall);
    AddSubstitute<Label>(Defaults::call, Inst::kIdCall);
    AddSubstitute<Mem>(Defaults::call, Inst::kIdCall);
    AddSubstitute<Gp, Imm>(Defaults::mov, Inst::kIdMov);
    AddSubstitute<Gp, Gp>(Defaults::mov, Inst::kIdMov);
    AddSubstitute<Gp, Mem>(Defaults::mov, Inst::kIdMov);
    AddSubstitute<Mem, Imm>(Defaults::mov, Inst::kIdMov);
    AddSubstitute<Mem, Gp>(Defaults::mov, Inst::kIdMov);
    AddSubstitute<Gp>(Defaults::jmp, Inst::kIdJmp);
    AddSubstitute<Label>(Defaults::jmp, Inst::kIdJmp);
    AddSubstitute<Mem>(Defaults::jmp, Inst::kIdJmp);
    AddSubstitute(Defaults::ret, Inst::kIdRet);
}