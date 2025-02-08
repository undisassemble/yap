#pragma once

#include "packer.hpp"
#include "asm.hpp"

/// <summary>
/// Converts chosen functions
/// </summary>
/// <param name="pPE">PE that contains functions to be virtualized</param>
/// <returns>Success/failure</returns>
bool Virtualize(_In_ Asm* pPE);