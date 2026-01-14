/*!
 * @file substitution.hpp
 * @author undisassemble
 * @brief Reassembler instruction substitution related functions
 * @version 0.0.0
 * @date 2026-01-14
 * @copyright MIT License
 */

#pragma once
#include "relib/asm.hpp"
#include "assembler.hpp"

using namespace x86;

typedef bool (__stdcall* SubstitutionCallback_t)(ProtectedAssembler*, const Operand_&, const Operand_&, const Operand_&, const Operand_&);

/*!
 * @brief Makes a unique ID for each instruction identity.
 * 
 * @param mnemonic Mnemonic of the instruction.
 * @param o0 First operand type of the instruction.
 * @param o1 Second operand type of the instruction.
 * @param o2 Third operand type of the instruction.
 * @param o3 Fourth operand type of the instruction.
 * @return DWORD Unique ID for the instruction.
 */
DWORD MakeSubstitutionID(Inst::Id mnemonic, OperandType o0, OperandType o1, OperandType o2, OperandType o3);

/*!
 * @brief 
 * @warning If there is an existing substitution with the same SubstitutionID, it will be overwritten.
 * 
 * @param callback 
 * @param SubstitutionID 
 */
void AddSubstitute(SubstitutionCallback_t callback, DWORD SubstitutionID);

/*!
 * @brief 
 * @warning If there is an existing substitution with the same SubstitutionID, it will be overwritten.
 * 
 * @param callback 
 * @param mnemonic 
 * @param o0 
 * @param o1 
 * @param o2 
 * @param o3 
 */
void AddSubstitute(SubstitutionCallback_t callback, Inst::Id mnemonic, OperandType o0 = OperandType::kNone, OperandType o1 = OperandType::kNone, OperandType o2 = OperandType::kNone, OperandType o3 = OperandType::kNone);

template<typename o0 = Operand_, typename o1 = Operand_, typename o2 = Operand_, typename o3 = Operand_>
void AddSubstitute(bool (__stdcall* callback)(ProtectedAssembler*, const o0&, const o1&, const o2&, const o3&), Inst::Id mnemonic) {
    OperandType _o0_t = std::is_same<o0, Operand_>::value ? OperandType::kNone : o0().opType();
    OperandType _o1_t = std::is_same<o1, Operand_>::value ? OperandType::kNone : o1().opType();
    OperandType _o2_t = std::is_same<o2, Operand_>::value ? OperandType::kNone : o2().opType();
    OperandType _o3_t = std::is_same<o3, Operand_>::value ? OperandType::kNone : o3().opType();
    AddSubstitute(reinterpret_cast<SubstitutionCallback_t>(callback), mnemonic, _o0_t, _o1_t, _o2_t, _o3_t);
}

extern Vector<std::pair<DWORD, SubstitutionCallback_t>> SubstitutionDict;

void RegisterDefaultSubstitutions();