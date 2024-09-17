#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

BOOL WINAPI DllMain(_In_ HINSTANCE hInstDll, _In_ DWORD dwReason, _In_ LPVOID pReserved) {
	if (dwReason == DLL_PROCESS_ATTACH && MessageBoxA(NULL, "Either this application is not packed or you did not link the SDK properly, please read yap.h!", "Warning", MB_ICONWARNING | MB_OKCANCEL) == IDCANCEL) ExitProcess(0);
	return TRUE;
}

extern "C" __declspec(dllexport) bool CheckForDebuggers() { return false; }
extern "C" __declspec(dllexport) bool CheckThreadsAlive() { return true; }