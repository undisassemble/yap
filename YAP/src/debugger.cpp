#include "util.hpp"
#include "debugger.hpp"
#include <tlhelp32.h>
#include <basetsd.h>
#include <errhandlingapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <processthreadsapi.h>
#include <winnt.h>
#include <winternl.h>
#include <dbghelp.h>

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 100
#endif

Vector<MODULEENTRY32> Modules;
BOOL Syms;
HANDLE hParent;
HANDLE hThread;

void LogExceptionRecord(_In_ EXCEPTION_RECORD* pExceptionRecord);
void AddressToSymbol(_In_ QWORD Address, _Out_ char* buf, _In_ size_t buf_sz);

void LaunchAsDebugger() {
	// Open log file
	hLogFile = CreateFileA("except.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hLogFile || hLogFile == INVALID_HANDLE_VALUE) {
		exit(1);
	}

	// Find parent
	DWORD dwParentId = 0;
	PROCESS_BASIC_INFORMATION info = { 0 };
	if (NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(PROCESS_BASIC_INFORMATION), NULL)) {
		LOG(Failed, MODULE_YAP, "Failed to get parent PID\n");
		exit(1);
	}
	dwParentId = (DWORD)info.InheritedFromUniqueProcessId;
	LOG(Info, MODULE_YAP, "Parent PID: %d\n", dwParentId);
	if (!DebugActiveProcess(dwParentId)) {
		LOG(Failed, MODULE_YAP, "Failed to attach to parent (%d)\n", GetLastError());
		exit(1);
	}
	hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentId);
	if (!hParent)
		LOG(Warning, MODULE_YAP, "Failed to open handle to parent, won\'t be able to provide stack traces. (%d)\n", GetLastError());

    // Initialize symbols
    if (hParent && !(Syms = SymInitialize(hParent, NULL, TRUE)))
        LOG(Warning, MODULE_YAP, "Failed to initialize symbols, won\'t be able to provice function names. (%d)\n", GetLastError());

    DEBUG_EVENT event = { 0 };
	MODULEENTRY32 entry = { 0 };
	entry.dwSize = sizeof(MODULEENTRY32);
	CONTEXT context;
	while (1) {
		if (WaitForDebugEvent(&event, INFINITE)) {
			if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && event.dwProcessId == dwParentId) {
				LOG(Info_Extended, MODULE_YAP, "Process exited: %lx\n", event.u.ExitProcess.dwExitCode);
				break;
			}

			else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && event.u.Exception.ExceptionRecord.ExceptionCode != 0x6ba) {
				LOG(Failed, MODULE_YAP, "----- Exception recorded -----\n");
				LOG(Info_Extended, MODULE_YAP, "Build: " __YAP_VERSION__ " " __YAP_BUILD__ "\n");
				
				// Log registers
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                ZeroMemory(&context, sizeof(CONTEXT));
                context.ContextFlags = CONTEXT_ALL;
				if (!hThread) {
					LOG(Warning, MODULE_YAP, "Failed to open crashed thread (%d)\n", GetLastError());
				} else if (SuspendThread(hThread) == _UI32_MAX) {
					LOG(Warning, MODULE_YAP, "Failed to suspend thread (%d)\n", GetLastError());
				} else if (!GetThreadContext(hThread, &context)) {
					LOG(Warning, MODULE_YAP, "Failed to get thread context (%d)\n", GetLastError());
				} else {
					// This isnt working, I dont know why
					LOG(Info_Extended, MODULE_YAP, "--- CONTEXT ---\n");
                    LOG(Info_Extended, MODULE_YAP, "RIP: %p\n", context.Rip);
					LOG(Info_Extended, MODULE_YAP, "RAX: %p\n", context.Rax);
					LOG(Info_Extended, MODULE_YAP, "RCX: %p\n", context.Rcx);
					LOG(Info_Extended, MODULE_YAP, "RDX: %p\n", context.Rdx);
					LOG(Info_Extended, MODULE_YAP, "RBX: %p\n", context.Rbx);
					LOG(Info_Extended, MODULE_YAP, "RSP: %p\n", context.Rsp);
					LOG(Info_Extended, MODULE_YAP, "RBP: %p\n", context.Rbp);
					LOG(Info_Extended, MODULE_YAP, "RSI: %p\n", context.Rsi);
					LOG(Info_Extended, MODULE_YAP, "RDI: %p\n", context.Rdi);
					LOG(Info_Extended, MODULE_YAP, "R8:  %p\n", context.R8);
					LOG(Info_Extended, MODULE_YAP, "R9:  %p\n", context.R9);
					LOG(Info_Extended, MODULE_YAP, "R10: %p\n", context.R10);
					LOG(Info_Extended, MODULE_YAP, "R11: %p\n", context.R11);
					LOG(Info_Extended, MODULE_YAP, "R12: %p\n", context.R12);
					LOG(Info_Extended, MODULE_YAP, "R13: %p\n", context.R13);
					LOG(Info_Extended, MODULE_YAP, "R14: %p\n", context.R14);
					LOG(Info_Extended, MODULE_YAP, "R15: %p\n", context.R15);
					ResumeThread(hThread);
				}

				// Log list of loaded modules
				Modules.Release();
				HANDLE hSnap;
				do {
					hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
				} while (hSnap == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);
				if (hSnap == INVALID_HANDLE_VALUE) {
					LOG(Warning, MODULE_YAP, "Could not get list of modules (%d)\n", GetLastError());
				} else {
					LOG(Info_Extended, MODULE_YAP, "--- MODULES ---\n");
					Module32First(hSnap, &entry);
					do {
						Modules.Push(entry);
						LOG(Info_Extended, MODULE_YAP, "%s: \t0x%p -> 0x%p\n", entry.szModule, entry.modBaseAddr, entry.modBaseAddr + entry.modBaseSize);
					} while (Module32Next(hSnap, &entry));
				}
				CloseHandle(hSnap);

				// Log exceptions
				LOG(Info_Extended, MODULE_YAP, "--- RECORD(S) ---\n");
				LogExceptionRecord(&event.u.Exception.ExceptionRecord);

				// Stack trace
				if (hParent && hThread) {
					LOG(Info_Extended, MODULE_YAP, "--- STACK ---\n");
					STACKFRAME64 frame = { 0 };
					frame.AddrPC.Offset = context.Rip;
                    frame.AddrPC.Mode = AddrModeFlat;
					frame.AddrStack.Offset = context.Rsp;
                    frame.AddrStack.Mode = AddrModeFlat;
                    frame.AddrFrame.Offset = context.Rbp;
                    frame.AddrFrame.Mode = AddrModeFlat;
                    char buf[MAX_PATH] = { 0 };
                    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
                        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, hParent, hThread, &frame, &context, NULL, NULL, NULL, NULL)) break;
                        
                        AddressToSymbol(frame.AddrPC.Offset, buf, MAX_PATH);
                        LOG(Info_Extended, MODULE_YAP, "Called from 0x%p (%s)\n", frame.AddrPC.Offset, buf);

                        if (i == MAX_STACK_DEPTH - 1) {
                            LOG(Info_Extended, MODULE_YAP, "Max stack depth reached: %d entries\n", MAX_STACK_DEPTH);
                        }
                    }
                }
				LOG(Info_Extended, MODULE_YAP, "----- End of exception -----\n\n\n\n");
			}
			ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		}
	}
	DebugActiveProcessStop(dwParentId);
	exit(0);
}


void AddressToSymbol(_In_ QWORD Address, _Out_ char* buf, _In_ size_t buf_sz) {
    buf[0] = 0;

    // First try SymFromAddr
    if (Syms) {
        SYMBOL_INFO* pSymbol = NULL;
        pSymbol = reinterpret_cast<SYMBOL_INFO*>(malloc(sizeof(SYMBOL_INFO) + MAX_PATH));
        pSymbol->MaxNameLen = MAX_PATH;
        pSymbol->MaxNameLen = MAX_PATH;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->NameLen = 0;
        pSymbol->Name[0] = 0;
        DWORD64 off = 0;
        if (SymFromAddr(hParent, Address, &off, pSymbol) && pSymbol->Name[0] && pSymbol->NameLen) {
            snprintf(buf, buf_sz, "%s + 0x%08lx", pSymbol->Name, off);
            return;
        }
    }

    // If that fails, just do offset from module
    for (int i = 0; i < Modules.Size(); i++) {
        if (Address >= Modules[i].modBaseAddr && Address < Modules[i].modBaseAddr + Modules[i].modBaseSize) {
            snprintf(buf, buf_sz, "%s + 0x%08lx", Modules[i].szModule, Address - reinterpret_cast<QWORD>(Modules[i].modBaseAddr));
            return;
        }
    }
}

void LogExceptionRecord(_In_ EXCEPTION_RECORD* pExceptionRecord) {
	if (pExceptionRecord) {
		switch (pExceptionRecord->ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_ACCESS_VIOLATION\n");
			if (pExceptionRecord->NumberParameters >= 2) LOG(Info_Extended, MODULE_YAP, "Attempted %c operation on address 0x%p\n", pExceptionRecord->ExceptionInformation[0] == 0 ? 'R' : (pExceptionRecord->ExceptionInformation[0] == 1 ? 'W' : (pExceptionRecord->ExceptionInformation[0] == 8 ? 'X' : '-')), pExceptionRecord->ExceptionInformation[1]);
			break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
			break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
			break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_FLT_INVALID_OPERATION\n");
			break;
		case EXCEPTION_FLT_STACK_CHECK:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_FLT_STACK_CHECK\n");
			break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_ILLEGAL_INSTRUCTION\n");
			break;
		case EXCEPTION_IN_PAGE_ERROR:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_IN_PAGE_ERROR\n");
			break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_INT_DIVIDE_BY_ZERO\n");
			break;
		case EXCEPTION_STACK_OVERFLOW:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_STACK_OVERFLOW\n");
			break;
		case STATUS_HEAP_CORRUPTION:
			LOG(Info_Extended, MODULE_YAP, "Code: STATUS_HEAP_CORRUPTION\n");
			break;
		case EXCEPTION_BREAKPOINT:
			LOG(Info_Extended, MODULE_YAP, "Code: EXCEPTION_BREAKPOINT\n");
			break;
		default:
			LOG(Info_Extended, MODULE_YAP, "Code: %#010lx\n", pExceptionRecord->ExceptionCode);
		}
        char buf[MAX_PATH] = { 0 };
        AddressToSymbol(pExceptionRecord->ExceptionAddress, buf, MAX_PATH);
		LOG(Info_Extended, MODULE_YAP, "Address: 0x%p (%s)\n", pExceptionRecord->ExceptionAddress, buf);
		for (int i = 0; i < Modules.Size(); i++) {
			if (pExceptionRecord->ExceptionAddress >= Modules[i].modBaseAddr && pExceptionRecord->ExceptionAddress < Modules[i].modBaseAddr + Modules[i].modBaseSize) {
				LOG(Info_Extended, MODULE_YAP, "RVA: 0x%08x\n", reinterpret_cast<uint64_t>(pExceptionRecord->ExceptionAddress) - reinterpret_cast<uint64_t>(Modules[i].modBaseAddr));
				LOG(Info_Extended, MODULE_YAP, "In module %s\n", Modules[i].szModule);
				break;
			}
		}
		if (pExceptionRecord->ExceptionRecord) LogExceptionRecord(pExceptionRecord->ExceptionRecord);
	}
}