#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define STATUS_NOT_IMPLEMENTED 0xC0000002

BOOL WINAPI DllMain(_In_ HINSTANCE hInstDll, _In_ DWORD dwReason, _In_ LPVOID pReserved) {
	if (dwReason == DLL_PROCESS_ATTACH && MessageBoxA(NULL, "Either this application is not packed or you did not link the SDK properly, please read yap.h!", "Warning", MB_ICONWARNING | MB_OKCANCEL) == IDCANCEL) ExitProcess(0);
	return TRUE;
}

#define YAP_EXPORT(type) extern "C" __declspec(dllexport) type __stdcall

YAP_EXPORT(bool) CheckForDebuggers() { return false; }
YAP_EXPORT(HMODULE) GetSelf() { return NULL; }
YAP_EXPORT(LONG) YAP_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, void* ClientId) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, void* ClientId) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtResumeProcess(HANDLE ProcessHandle) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSetInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSetInformationThread(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSetThreadExecutionState(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSuspendProcess(HANDLE ProcessHandle) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtTerminateProcess(HANDLE ProcessHandle, LONG ExitStatus) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtTerminateThread(HANDLE ThreadHandle, LONG ExitStatus) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtClose(HANDLE Handle) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(LONG) YAP_NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, PCONTEXT ThreadContext, void* InitialTeb, BOOLEAN CreateSuspended) { return STATUS_NOT_IMPLEMENTED; }
YAP_EXPORT(HANDLE) YAP_GetCurrentThread() { return NULL; }
YAP_EXPORT(DWORD) YAP_GetCurrentThreadId() { return 0; }
YAP_EXPORT(HANDLE) YAP_GetCurrentProcess() { return NULL; }
YAP_EXPORT(DWORD) YAP_GetCurrentProcessId() { return 0; }
YAP_EXPORT(BYTE) ExtractSyscallID(void* pFunc) { return NULL; }