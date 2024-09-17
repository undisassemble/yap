/// PLEASE READ ME!
/// 
/// Functions provided in this header and in yap.dll DO NOT DO ANYTHING UNLESS YOUR APPLICATION HAS BEEN PACKED!
/// Every function is handled internally by the packer, meaning you do not need to distribute yap.dll with your application, because it doesn't do anything.
/// Please make sure that you link with yap.dll specifically, and do not rename it, otherwise the packer will not be able to resolve the imports!
/// All functions are provided if they were imported, regardless of configuration options when packing.
/// You also cannot use GetProcAddress to get access to these functions.
/// 
/// Have a good day :)

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define __YAP_VERSION__ "0.0.0"

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Manually check for attached debuggers
/// </summary>
/// <returns>true if debugger is found, false otherwise</returns>
__declspec(dllimport) bool CheckForDebuggers();

/// <summary>
/// Check to ensure protection threads are running
/// </summary>
/// <returns>true if still running or disabled when packed, false if threads died/were killed</returns>
__declspec(dllimport) bool CheckThreadsAlive();

#ifdef __cplusplus
}
#endif