/// PLEASE READ ME!
/// 
/// Functions provided in this header and in yap.dll DO NOT DO ANYTHING UNLESS YOUR APPLICATION HAS BEEN PACKED!
/// Every function is handled internally by the packer, meaning you do not need to distribute yap.dll with your application, because it doesn't do anything.
/// Please make sure that you link with yap.dll specifically, and do not rename it, otherwise the packer will not be able to resolve the imports!
/// All functions are provided if they were imported, regardless of configuration options when packing.
/// You also cannot use GetProcAddress to get access to these functions.
/// 
/// Define YAP_EDR to import YAP-based WINAPI functions
/// 
/// Have a good day :)

#pragma once

#ifndef _WIN64
#error YAP can only be used on 64-bit binaries!
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define __YAP_VERSION__ "0.0.0"
#define YAP_IMPORT(type) __declspec(dllimport) type __stdcall

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Manually check for attached debuggers.
/// It is highly recommended that you use this in your main thread, as no protective threads are spawned by the packer.
/// </summary>
/// <returns>true if debugger is found, false otherwise</returns>
YAP_IMPORT(bool) CheckForDebuggers();

/// <summary>
/// If using anti-dump, GetModuleHandle(NULL) will return NULL, use this instead.
/// </summary>
/// <returns>Program base address</returns>
YAP_IMPORT(HMODULE) GetSelf();

// These all return STATUS_NOT_IMPLEMENTED if not packed and STATUS_NOT_FOUND if the function cannot be found
// If the NTDLL function is hooked, it will terminate the process
#ifdef YAP_EDR
#define STATUS_NOT_IMPLEMENTED 0xC0000002
YAP_IMPORT(LONG) YAP_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
YAP_IMPORT(LONG) YAP_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
YAP_IMPORT(LONG) YAP_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
YAP_IMPORT(LONG) YAP_NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
YAP_IMPORT(LONG) YAP_NtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
YAP_IMPORT(LONG) YAP_NtGetNextThread(HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
YAP_IMPORT(LONG) YAP_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, void* ClientId);
YAP_IMPORT(LONG) YAP_NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, void* ClientId);
YAP_IMPORT(LONG) YAP_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
YAP_IMPORT(LONG) YAP_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
YAP_IMPORT(LONG) YAP_NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
YAP_IMPORT(LONG) YAP_NtResumeProcess(HANDLE ProcessHandle);
YAP_IMPORT(LONG) YAP_NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext);
YAP_IMPORT(LONG) YAP_NtSetInformationProcess(HANDLE ProcessHandle, int ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
YAP_IMPORT(LONG) YAP_NtSetInformationThread(HANDLE ThreadHandle, int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);
YAP_IMPORT(LONG) YAP_NtSetThreadExecutionState(EXECUTION_STATE NewFlags, EXECUTION_STATE* PreviousFlags);
YAP_IMPORT(LONG) YAP_NtSuspendProcess(HANDLE ProcessHandle);
YAP_IMPORT(LONG) YAP_NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
YAP_IMPORT(LONG) YAP_NtTerminateProcess(HANDLE ProcessHandle, LONG ExitStatus);
YAP_IMPORT(LONG) YAP_NtTerminateThread(HANDLE ThreadHandle, LONG ExitStatus);
YAP_IMPORT(LONG) YAP_NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
YAP_IMPORT(LONG) YAP_NtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, void* ClientId, PCONTEXT ThreadContext, void* InitialTeb, BOOLEAN CreateSuspended);
YAP_IMPORT(LONG) YAP_NtClose(HANDLE Handle);
YAP_IMPORT(HANDLE) YAP_GetCurrentThread();
YAP_IMPORT(DWORD) YAP_GetCurrentThreadId();
YAP_IMPORT(HANDLE) YAP_GetCurrentProcess();
YAP_IMPORT(DWORD) YAP_GetCurrentProcessId();
#endif
#ifdef __cplusplus
}
#endif
#undef YAP_IMPORT