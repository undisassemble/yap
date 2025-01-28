/// PLEASE READ ME!
/// 
/// Functions provided in this header and in yap.dll DO NOT DO ANYTHING UNLESS YOUR APPLICATION HAS BEEN PACKED!
/// Every function is handled internally by the packer, meaning you do not need to distribute yap.dll with your application, because it doesn't do anything.
/// Please make sure that you link with yap.dll specifically, and do not rename it, otherwise the packer will not be able to resolve the imports!
/// All functions are provided if they were imported, regardless of configuration options when packing.
/// You also cannot use GetProcAddress to get access to these functions.
/// 
/// You don't have to link with yap.dll if you only use reasm macros.
/// 
/// Have a good day :)

#pragma once

#ifndef _WIN64
#error YAP can only be used on 64-bit Windows binaries!
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define __YAP_VERSION__ "0.0.0"
#define YAP_IMPORT(type) __declspec(dllimport) type __stdcall

#ifdef __cplusplus
extern "C" {
#else
#include <stdbool.h>
#endif

/// <summary>
/// Manually check for attached debuggers.
/// It is highly recommended that you use this in your main thread, as no protective threads are spawned by the packer.
/// Only the main thread of the application can check for hardware breakpoints.
/// </summary>
/// <returns>true if debugger is found, false otherwise</returns>
YAP_IMPORT(bool) CheckForDebuggers();

/// <summary>
/// If using anti-dump, GetModuleHandle(NULL) will return NULL, use this instead.
/// </summary>
/// <returns>Program base address</returns>
YAP_IMPORT(HMODULE) GetSelf();

#ifdef __cplusplus
}
#endif
#undef YAP_IMPORT


// Asm macros
#define YAP_OP_REASM_MUTATION 0b10000000
#define YAP_OP_REASM_SUB      0b00000010
#ifdef __MINGW64__
#define YAP_OP(x) __asm__ volatile (".byte 0x67, 0x48, 0x0F, 0x1F, 0x04, 0x25, %c0, 0x80, 0x65, 0x89" : : "i" (x & 0xFF))
#else
#define YAP_OP(x) __asm nop qword [0x89658000 | (x)]
#endif

// Set mutation level (0 = disabled)
#define YAP_MUTATIONLEVEL(level) YAP_OP(YAP_OP_REASM_MUTATION | (level & 0b1111111))

// Enable/disable substitution (1/0 or true/false, only checks lower bit)
#define YAP_SUBSTITUTION(enabled) YAP_OP(YAP_OP_REASM_SUB | (enabled & 1))