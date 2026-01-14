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

/*!
 * @brief The callback that is called when a substitution is hit.
 * @note Returning `false` will cause the assembler to emit the original, unmodified instruction. Return `true` if your substitution mimics the behavior of the original instruction to prevent the instruction from acting twice.
 */
typedef bool (__stdcall* SubstitutionCallback_t)(ProtectedAssembler*, const Operand_&, const Operand_&, const Operand_&, const Operand_&);

/*!
 * @brief Makes a unique ID for each instruction identity.
 * 
 * @param [in] mnemonic Mnemonic of the instruction.
 * @param [in] o0 First operand type of the instruction.
 * @param [in] o1 Second operand type of the instruction.
 * @param [in] o2 Third operand type of the instruction.
 * @param [in] o3 Fourth operand type of the instruction.
 * @return DWORD Unique ID for the instruction.
 */
DWORD MakeSubstitutionID(_In_ Inst::Id mnemonic, _In_ OperandType o0, _In_ OperandType o1, _In_ OperandType o2, _In_ OperandType o3);

/*!
 * @brief Adds a substitution.
 * @warning If there is an existing substitution with the same SubstitutionID, it will be overwritten.
 * 
 * @param [in] callback The function to be called when the instruction described by SubstitutionID is reached.
 * @param [in] SubstitutionID The definition of the instruction to be substituted.
 * 
 * @see SubstitutionCallback_t
 * @see MakeSubstitutionID
 */
void AddSubstitute(_In_ SubstitutionCallback_t callback, _In_ DWORD SubstitutionID);

/*!
 * @brief Adds a substitution.
 * @warning If there is an existing substitution with the same SubstitutionID, it will be overwritten.
 * 
 * @param [in] callback The function to be called when the instruction described by SubstitutionID is reached.
 * @param [in] mnemonic Mnemonic of the instruction to be substituted.
 * @param [in] o0 Type of the first operand, can be `OperandType::kNone`, `OperandType::kReg`, `OperandType::kMem`, `OperandType::kRegList`, `OperandType::kImm`, or `OperandType:kLabel`.
 * @param [in] o1 Type of the second operand, can be `OperandType::kNone`, `OperandType::kReg`, `OperandType::kMem`, `OperandType::kRegList`, `OperandType::kImm`, or `OperandType:kLabel`.
 * @param [in] o2 Type of the third operand, can be `OperandType::kNone`, `OperandType::kReg`, `OperandType::kMem`, `OperandType::kRegList`, `OperandType::kImm`, or `OperandType:kLabel`.
 * @param [in] o3 Type of the fourth operand, can be `OperandType::kNone`, `OperandType::kReg`, `OperandType::kMem`, `OperandType::kRegList`, `OperandType::kImm`, or `OperandType:kLabel`.
 * 
 * @see SubstitutionCallback_t
 */
void AddSubstitute(_In_ SubstitutionCallback_t callback, _In_ Inst::Id mnemonic, _In_ OperandType o0 = OperandType::kNone, _In_ OperandType o1 = OperandType::kNone, _In_ OperandType o2 = OperandType::kNone, _In_ OperandType o3 = OperandType::kNone);

template<typename o0 = Operand_, typename o1 = Operand_, typename o2 = Operand_, typename o3 = Operand_>
void AddSubstitute(_In_ bool (__stdcall* callback)(ProtectedAssembler*, const o0&, const o1&, const o2&, const o3&), _In_ Inst::Id mnemonic) {
    OperandType _o0_t = std::is_same<o0, Operand_>::value ? OperandType::kNone : o0().opType();
    OperandType _o1_t = std::is_same<o1, Operand_>::value ? OperandType::kNone : o1().opType();
    OperandType _o2_t = std::is_same<o2, Operand_>::value ? OperandType::kNone : o2().opType();
    OperandType _o3_t = std::is_same<o3, Operand_>::value ? OperandType::kNone : o3().opType();
    AddSubstitute(reinterpret_cast<SubstitutionCallback_t>(callback), mnemonic, _o0_t, _o1_t, _o2_t, _o3_t);
}

extern Vector<std::pair<DWORD, SubstitutionCallback_t>> SubstitutionDict;

void RegisterDefaultSubstitutions();