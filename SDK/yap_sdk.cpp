/*!
 * @file yap_sdk.cpp
 * @author undisassemble
 * @brief SDK dll
 * @version 0.0.0
 * @date 2025-08-28
 * @copyright MIT License
 */

#ifndef _WIN64
#error YAP can only be used on 64-bit Windows binaries!
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define STATUS_NOT_IMPLEMENTED 0xC0000002

BOOL WINAPI DllMain(_In_ HINSTANCE hInstDll, _In_ DWORD dwReason, _In_ LPVOID pReserved) {
	if (dwReason == DLL_PROCESS_ATTACH && MessageBoxA(NULL, "Either this application is not packed or you did not link the SDK properly, please read yap.h!", "Warning", MB_ICONWARNING | MB_OKCANCEL) == IDCANCEL) ExitProcess(0);
	return TRUE;
}

#define YAP_EXPORT(type) extern "C" __declspec(dllexport) type __stdcall

YAP_EXPORT(bool) CheckForDebuggers(bool p0) { return false; }
YAP_EXPORT(HMODULE) GetSelf() { return NULL; }