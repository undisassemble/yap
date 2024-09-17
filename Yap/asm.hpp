#pragma once

#include "util.h"
#include "pe.hpp"

enum LineType : BYTE {
	Decoded,
	Encoded,
	Embed,
	RawInsert,
	Padding,
	JumpTable,
	Pointer
};

struct Line {
	LineType Type : 4;
	bool bTLSCallback : 1 = false; // Line is the entry point of a TLS callback
	bool bEntryPoint : 1 = false; // Line is the programs OEP
	bool bRelative : 1 = false; // Jump table is relative to first entry
	DWORD OldRVA = 0;
	DWORD NewRVA = 0;
	union {
		struct {
			ZydisDecodedInstruction Instruction;
			ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];
		} Decoded;
		struct {
			BYTE Raw[ZYDIS_MAX_INSTRUCTION_LENGTH];
			BYTE Size;
		} Encoded;
		struct {
			DWORD Size;
		} Embed;
		Buffer RawInsert;
		struct {
			DWORD Size;
		} Padding;
		struct {
			DWORD Value;
			DWORD Base; // Only if it's relative
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
	DWORD OldRVA;
	DWORD NewRVA;
	DWORD OldSize;
	DWORD NewSize;
	Buffer Assembled;
	Vector<Line>* Lines;
};

DWORD GetLineSize(_In_ Line line);

/// <summary>
/// Encodes an array of relocation RVAs into the relocation directory.
/// </summary>
/// <param name="Relocations">Array of RVAs that need relocations, should be sorted from least to greatest.</param>
/// <returns>Buffer containing relocation directory</returns>
Buffer GenerateRelocSection(Vector<DWORD> Relocations);

/// <summary>
/// Handles disassembly, assembly, and assembly modifications
/// </summary>
class Asm : public PE {
private:
	bool DisasmRecursive(_In_ DWORD dwRVA);
	bool CheckRuntimeFunction(_In_ RUNTIME_FUNCTION* pFunc, _In_ bool bFixAddr = false);
	Vector<Function> FindFunctionsRecursive(_In_ DWORD dwRVA);
	Vector<Function> _CheckRuntimeFunction2(_In_ RUNTIME_FUNCTION* pFunc);

protected:
	Vector<AsmSection> Sections;
	Vector<DWORD> JumpTables;
	ZydisDecoder Decoder;
	Vector<DWORD> Processed;

public:
	Vector<Function> FindFunctions();

	Asm();
	Asm(_In_ char* sFileName);
	Asm(_In_ HANDLE hFile);
	~Asm();

	DWORD TranslateOldAddress(_In_ DWORD dwRVA);

	DWORD FindPosition(_In_ DWORD dwSec, _In_ DWORD dwRVA);
	DWORD FindIndex(_In_ DWORD dwSec, _In_ DWORD dwRVA);
	DWORD FindSectionIndex(_In_ DWORD dwRVA);

	bool Disassemble();

	/// <summary>
	/// Assembles existing assembly
	/// </summary>
	/// <returns>Success</returns>
	bool Assemble();

	/// <summary>
	/// Inserts new asm instruction
	/// </summary>
	/// <param name="iIndex">Index to insert asm</param>
	/// <param name="pLine">Assembly to be inserted</param>
	/// <returns>Success/failure</returns>
	void InsertLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ Line Line);

	bool InsertNewLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex, _In_ ZydisEncoderRequest* pRequest);
	void DeleteLine(_In_ DWORD SectionIndex, _In_ DWORD LineIndex);
	void RemoveData(_In_ DWORD dwRVA, _In_ DWORD dwSize);

	DWORD GetAssembledSize(_In_ DWORD SectionIndex);

	size_t GetNumLines();
	Vector<AsmSection> GetSections();

	/// <summary>
	/// Fixes addresses in existing asm code
	/// </summary>
	bool FixAddresses();
};