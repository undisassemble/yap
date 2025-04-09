/*!
 * @file asm.hpp
 * @author undisassemble
 * @brief Disassembly related definitions
 * @version 0.0.0
 * @date 2025-04-08
 * @copyright MIT License
 * @bug Crashes due to `_pei386_runtime_relocator`.
 */

#pragma once

#include "util.hpp"
#include "pe.hpp"
#include <asmjit/asmjit.h>

/*!
 * @brief Type of `Line`.
 * 
 * @see Line
 */
enum LineType : BYTE {
	Decoded,   //!< Line is a decoded instruction.
	Embed,     //!< Line is the address and size of raw data.
	RawInsert, //!< Raw data that should be inserted from a different buffer.
	Padding,   //!< Line is additional padding created when the binary is loaded.
	JumpTable, //!< Line is a jump table case.
	Pointer,   //!< Line is a pointer.
};

#ifndef ENABLE_DUMPING
/*!
 * @brief Memory reduced version of `ZydisDecodedInstruction`.
 */
struct DecodedInstruction {
	ZydisMnemonic mnemonic;                //!< Mnemonic of the instruction.
	BYTE length;                           //!< Encoded size of the instruction.
	union {
		BYTE operand_count;                //!< Number of operands in the instruction.
		BYTE operand_count_visible;        //!< Number of operands in the instruction.
	};
	ZydisInstructionAttributes attributes; //!< Instruction attributes.

	void operator=(_In_ ZydisDecodedInstruction instruction);
	operator ZydisDecodedInstruction() const;
};

/*!
 * @brief Memory reduced version of `ZydisDecodedOperand`.
 */
struct DecodedOperand {
	ZydisOperandType type;          //!< Type of operand.
	BYTE size;                      //!< Size of the operand data (in bits). E.g. rax = 64, eax = 32, ax = 16, al = 8.
	union {
		ZydisDecodedOperandReg reg; //!< Register.
		ZydisDecodedOperandMem mem; //!< Memory operand.
		struct {
			bool is_signed;         //!< If the immediate is signed, use `s` if true and `u` otherwise.
			union {
				uint64_t u;         //!< Value of the immediate.
				int64_t s;          //!< Value of the immediate.
			} value;
		} imm;
	};

	void operator=(_In_ ZydisDecodedOperand operand);
	operator ZydisDecodedOperand() const;
};
#else
typedef ZydisDecodedInstruction DecodedInstruction;
typedef ZydisDecodedOperand DecodedOperand;
#endif

/*!
 * @brief Represents a single line of disassembled code.
 * 
 * @see LineType
 * @see DecodedInstruction
 * @see DecodedOperand
 */
struct Line {
	LineType Type : 4;                      //!< The type of data stored, represents which members should be used.
	bool bRelative : 1 = false;             //!< Jump table is relative to first entry or request holds instruction index instead of absolute address (i.e. jmp 0 is jumping to the first instruction in the index, if doing this, make the instruction RIP-relative anyway).
	bool bRelocate : 1 = false;             //!< For requests that point to an old RVA and need to be relocated.
	DWORD OldRVA = 0;                       //!< Old RVA of the line.
	DWORD NewRVA = 0;                       //!< New RVA of the line. Only valid after `Asm::Assemble` called.
	union {
		struct {
			DecodedInstruction Instruction; //!< Instruction information.
			DecodedOperand Operands[4];     //!< Instruction operands.
			uint64_t refs;                  //!< Address of RIP-relative reference.
		} Decoded;
		struct {
			DWORD Size;                     //!< Size of data that should be embedded from `OldRVA`.
		} Embed;
		Buffer RawInsert;                   //!< Raw data that should be embedded.
		struct {
			DWORD Size;                     //!< Size of pad.
		} Padding;
		struct {
			DWORD Value;                    //!< RVA that the jump table references.
			DWORD Base;                     //!< Base added to `Value` when `bRelative` is set.
		} JumpTable;
		struct {
			union {
				DWORD RVA;                  //!< Pointer RVA.
				uint64_t Abs;               //!< Pointer absolute address.
			};
			bool IsAbs;                     //!< Whether the pointer is an absolute address or an RVA, use `Abs` if true and `RVA` if false.
		} Pointer;
	};
};

/*!
 * @brief Data for one section in the binary.
 */
struct AsmSection {
	DWORD OldRVA = 0;         //!< Section's original RVA.
	DWORD NewRVA = 0;         //!< Section's new RVA. Only valid after `Asm::Assemble` called.
	DWORD OldSize = 0;        //!< Section's original size;
	DWORD NewRawSize = 0;     //!< Section's new (raw) size. Only valid after `Asm::Assemble` called.
	DWORD NewVirtualSize = 0; //!< Section's new (virtual) size. Only valid after `Asm::Assemble` called. Should be >= `NewRawSize`.
	Vector<Line>* Lines;      //!< All lines in the section.
};

/*!
 * @brief Function information for partial loading.
 */
struct FunctionRange {
	Vector<DWORD> Entries; //!< Entry points of function.
	DWORD dwStart = 0; //!< Beginning RVA of the function.
	DWORD dwSize = 0; //!< Size of the function.
};

/*!
 * @brief Get the size of a line
 * 
 * @param [in] line Line to get the size of
 * @return Size of the line
 */
DWORD GetLineSize(_In_ const Line& line);

/*!
 * @brief Handles disassembly, assembly, and assembly modifications.
 * 
 * @see PE
 */
class Asm : public PE {
private:
	/*!
	 * @brief Disassembles data starting at `dwRVA`.
	 * 
	 * @param [in] dwRVA RVA to begin disassembly.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool DisasmRecursive(_In_ DWORD dwRVA);

	/*!
	 * @brief Disassembles or fixes exception info.
	 * 
	 * @param [in] pFunc Pointer to `RUNTIME_FUNCTION` to be checked.
	 * @param [in] bFixAddr `true` to fix addresses, `false` to disassemble functions.
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr = false);

	/*!
	 * @brief Get the next original line.
	 * 
	 * @param [in] dwSec Section to search.
	 * @param [in] dwIndex Index to begin search.
	 * @return Index of line.
	 * @retval _UI32_MAX Not found.
	 */
	DWORD GetNextOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex);

	/*!
	 * @brief Get the previous original line.
	 * 
	 * @param [in] dwSec Section to search.
	 * @param [in] dwIndex Index to begin search.
	 * @return Index of line.
	 * @retval _UI32_MAX Not found.
	 */
	DWORD GetPrevOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex);

protected:
	Vector<AsmSection> Sections;          //!< List of sections.
	Vector<DWORD> JumpTables;             //!< Jump table RVAs that have not yet been disassembled.
	ZydisDecoder Decoder;                 //!< Decoder instance.
	Vector<DWORD> Functions;              //!< Known function entries referenced in code.
	Vector<FunctionRange> FunctionRanges; //!< Functions found by `Analyze()`.
	uint64_t Progress = 0;                //!< Total number of disassembled bytes.
	uint64_t ToDo = 0;                    //!< Estimated number of bytes to disassemble.

public:
	Asm();
	~Asm();

	/*!
	 * @brief Parses PE from file.
	 * 
	 * @param [in] sFileName File name.
	 */
	Asm(_In_ char* sFileName);

	/*!
	 * @brief Parses PE from file.
	 * 
	 * @param [in] hFile File handle.
	 */
	Asm(_In_ HANDLE hFile);
	
	/*!
	 * @brief Finds functions compatible with partial loading.
	 * 
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool Analyze();

	/*!
	 * @brief Retrieves the function ranges found by `Analyze()`.
	 * 
	 * @return Discovered functions.
	 * 
	 * @see Analyze
	 * @see FunctionRange
	 */
	Vector<FunctionRange> GetDisassembledFunctionRanges();

	/*!
	 * @brief Strips debug info & symbols.
	 * 
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool Strip();

	/*!
	 * @brief Removes unnecessary data from the PE headers.
	 */
	void CleanHeaders();

	/*!
	 * @brief Translates a RVA from the original binary to the new assembled binary.
	 * @remark Should only be used after `Assemble()` has been called.
	 * 
	 * @param [in] dwRVA RVA to translate.
	 * @return New RVA.
	 * @retval NULL Unable to translate.
	 */
	DWORD TranslateOldAddress(_In_ DWORD dwRVA);

	/*!
	 * @brief Finds position where line with given RVA should be inserted.
	 * 
	 * @param [in] dwSec Section to insert line.
	 * @param [in] dwRVA RVA of line to insert.
	 * @return Index where line should be inserted.
	 * @retval _UI32_MAX-1 Line with RVA already exists.
	 * @retval _UI32_MAX Unable to find position.
	 */
	DWORD FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA);

	/*!
	 * @brief Finds line in section with given RVA.
	 * 
	 * @param [in] dwSec Section that contains the line.
	 * @param [in] dwRVA RVA of line to find.
	 * @return Index of line.
	 * @retval _UI32_MAX Line not found.
	 */
	DWORD FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA);
	
	/*!
	 * @brief Finds section that contains the given RVA.
	 * 
	 * @param [in] dwRVA RVA to find.
	 * @return Section index.
	 * @retval _UI32_MAX Section not found.
	 */
	DWORD FindSectionIndex(_In_ DWORD dwRVA);

	/*!
	 * @brief Disassembles application.
	 * 
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool Disassemble();

	/*!
	 * @brief Assembles application.
	 * 
	 * @retval true Success.
	 * @retval false Failure.
	 */
	bool Assemble();

	/*!
	 * @brief Inserts new asm instruction.
	 * 
	 * @param [in] SectionIndex Index of section to insert line.
	 * @param [in] LineIndex Index to insert into.
	 * @param [in] line Line to be inserted.
	 */
	void InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line line);

	/*!
	 * @brief Deletes asm instruction.
	 * 
	 * @param [in] SectionIndex Section containing line.
	 * @param [in] LineIndex Index of line to delete.
	 */
	void DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex);

	/*!
	 * @brief Removes data from given range.
	 * 
	 * @param [in] dwRVA RVA to begin removal.
	 * @param [in] dwSize Size of data to remove.
	 */
	void RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize);

	/*!
	 * @brief Calculates the new size of a section.
	 * 
	 * @param [in] SectionIndex Section index.
	 * @return Size of section.
	 */
	DWORD GetAssembledSize(_In_ DWORD SectionIndex);

	/*!
	 * @brief Retrieves list of sections.
	 * 
	 * @return Sections.
	 */
	Vector<AsmSection> GetSections();

	void DeleteSection(_In_ WORD wIndex) override;
};