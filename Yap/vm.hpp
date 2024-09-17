#pragma once

#include "packer.hpp"

struct VirtualizeResult {
	Vector<DWORD> RelocRVAs; // RVAs (pOriginal) of what needs to be included as a reloc entry
};

Label GenerateVMParser(_In_ PE* pPackedBinary, _In_ PE* pOriginal, _In_ PackerOptions Options, _In_ _ShellcodeData ShellcodeData, _In_ Assembler* pA, _In_ Label FunctionPtrs);

/// <summary>
/// </summary>
/// <param name="pOriginal"></param>
/// <param name="Options"></param>
/// <returns>Vector of RVAs where VM parser address must be placed (uint64_t)</returns>
VirtualizeResult Virtualize(_In_ PE* pOriginal, _In_ PackerOptions Options, _In_ Assembler* pA, _In_ Label FunctionPtrs);