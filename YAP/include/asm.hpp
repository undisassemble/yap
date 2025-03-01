#pragma once

#include "util.hpp"
#include "pe.hpp"
#include <asmjit/asmjit.h>

enum LineType : BYTE {
	Decoded,
	Embed,
	RawInsert,
	Padding,
	JumpTable,
	Pointer,
};

#ifndef ENABLE_DUMPING
struct DecodedInstruction {
	ZydisMnemonic mnemonic;
	BYTE length;
	union {
		BYTE operand_count;
		BYTE operand_count_visible;
	};
	ZydisInstructionAttributes attributes;

	void operator=(_In_ ZydisDecodedInstruction instruction);
	operator ZydisDecodedInstruction() const;
};

struct DecodedOperand {
	ZydisOperandType type;
	BYTE size;
	union {
		ZydisDecodedOperandReg reg;
		ZydisDecodedOperandMem mem;
		struct {
			bool is_signed;
			union {
				uint64_t u;
				int64_t s;
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

struct Line {
	LineType Type : 4;
	bool bRelative : 1 = false; ///< Jump table is relative to first entry or request holds instruction index instead of absolute address (i.e. jmp 0 is jumping to the first instruction in the index, if doing this, make the instruction RIP-relative anyway)
	bool bRelocate : 1 = false; ///< For requests that point to an old RVA and need to be relocated
	DWORD OldRVA = 0;
	DWORD NewRVA = 0;
	union {
		struct {
			DecodedInstruction Instruction;
			DecodedOperand Operands[4];
			uint64_t refs;
		} Decoded;
		struct {
			DWORD Size;
		} Embed;
		Buffer RawInsert;
		struct {
			DWORD Size;
		} Padding;
		struct {
			DWORD Value;
			DWORD Base; ///< Only used if `bRelative` is set
		} JumpTable;
		struct {
			union {
				DWORD RVA;
				uint64_t Abs;
			};
			bool IsAbs;
		} Pointer;
	};
};

struct AsmSection {
	DWORD OldRVA = 0;
	DWORD NewRVA = 0;
	DWORD OldSize = 0;
	DWORD NewRawSize = 0;
	DWORD NewVirtualSize = 0;
	Vector<Line>* Lines;
};

struct FunctionRange {
	Vector<DWORD> Entries;
	DWORD dwStart = 0;
	DWORD dwSize = 0;
};

/// 
/// Retrieves the encoded size of a line, in bytes.
/// 
DWORD GetLineSize(_In_ const Line& line);

/// 
/// Encodes an array of relocation RVAs into a valid relocation directory.
/// Relocations must be sorted from least to greatest.
/// 
Buffer GenerateRelocSection(Vector<DWORD> Relocations);

/// 
/// Handles disassembly, assembly, and assembly modifications
/// 
class Asm : public PE {
private:
	bool DisasmRecursive(_In_ DWORD dwRVA);
	bool CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr = false);
	DWORD GetNextOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex);
	DWORD GetPrevOriginal(_In_ DWORD dwSec, _In_ DWORD dwIndex);

protected:
	Vector<AsmSection> Sections;
	Vector<DWORD> JumpTables;
	ZydisDecoder Decoder;
	Vector<DWORD> Functions;
	Vector<FunctionRange> FunctionRanges;

public:

	Asm();
	Asm(_In_ char* sFileName);
	Asm(_In_ HANDLE hFile);
	~Asm();

	/// 
	/// Finds functions compatible with partial loading.
	/// 
	bool Analyze();

	/// 
	/// Retrieves the function ranges found by `Analyze()`.
	/// 
	Vector<FunctionRange> GetDisassembledFunctionRanges();

	/// 
	/// Strips debug info & symbols.
	/// 
	bool Strip();
	
	/// 
	/// Removes unnecessary data from the PE headers.
	/// 
	void CleanHeaders();

	/// 
	/// Translates a RVA from pre-assembly to post-assembly.
	/// Should only be used after a successful `Assemble()`.
	/// 
	DWORD TranslateOldAddress(_In_ DWORD dwRVA);

	/// 
	/// Finds position where line with given RVA should be inserted.
	/// Returns `_UI32_MAX - 1` if RVA already exists or `_UI32_MAX` on error.
	/// 
	DWORD FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA);
	
	/// 
	/// Finds line in section with given RVA.
	/// Returns `_UI32_MAX` if not found.
	/// 
	DWORD FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA);
	
	/// 
	/// Finds section that contains the given RVA.
	/// 
	DWORD FindSectionIndex(_In_ DWORD dwRVA);

	/// 
	/// Disassembles application.
	/// 
	bool Disassemble();

	/// 
	/// Assembles application.
	/// 
	bool Assemble();

	/// 
	/// Inserts new asm instruction.
	/// Use this as little as possible please, it's very slow.
	/// 
	void InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line Line);

	/// 
	/// Deletes asm instruction.
	/// 
	void DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex);
	
	/// 
	/// Removes data from given range.
	/// 
	void RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize);

	/// 
	/// Gets the new size of a section.
	/// Should only be used after a successful `Assemble()`.
	/// 
	DWORD GetAssembledSize(_In_ DWORD SectionIndex);

	/// 
	/// Gets the total number of lines.
	/// 
	size_t GetNumLines();
	
	/// 
	/// Gets section at index.
	/// 
	Vector<AsmSection> GetSections();

	void DeleteSection(_In_ WORD wIndex) override;
};