#include "util.hpp"
#include "asm.hpp"
#include "pe.hpp"
#include "packer.hpp"
#include "gui.hpp"
#include <TlHelp32.h>
#include <limits.h>
#include <minwinbase.h>
#include <processthreadsapi.h>
#include <time.h>
#include <stdarg.h>
#include <GLFW/glfw3.h>
#include <winnt.h>
#include <winternl.h>

// Forward declares
void LaunchAsDebugger();
DWORD WINAPI Begin(void* args);
namespace Console {
	void help(char* name);
	void buildversion();
	void version();
	void protect(char* input, char* output = NULL);
	void SetupConsole();
}

// Globals
Options_t Options;
Settings_t Settings;
Data_t Data;
HANDLE hLogFile = NULL;
HANDLE hStdOut = NULL;
Asm* pAssembly = NULL;

// Main function
int main(int argc, char** argv) {
	// Crash handler setup
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--crash-handler")) {
			LaunchAsDebugger();
			return 1;
		}
	}

	// General setup
	srand(time(NULL));
	hLogFile = CreateFile("yap.log.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hLogFile || hLogFile == INVALID_HANDLE_VALUE) {
		LOG(Failed, MODULE_YAP, "Failed to open logging file (%d)\n", GetLastError());
	}
	if (!IsDebuggerPresent()) {
		STARTUPINFOA si = { 0 };
		si.cb = sizeof(STARTUPINFOA);
		PROCESS_INFORMATION pi = { 0 };
		if (!CreateProcessA("YAPClient.exe", "YAPClient.exe --crash-handler", NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi)) {
			LOG(Warning, MODULE_YAP, "Failed to start crash handler (%d)\n", GetLastError());
		} else {
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
	}
	LoadSettings();
	
	// Look for - commands
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help")) {
			Console::SetupConsole();
			Console::help("YAP");
			return 0;
		} else if (!strcmp(argv[i], "--version")) {
			Console::SetupConsole();
			Console::buildversion();
			return 0;
		}
	}

	// Search CLI
	if (argc > 2) {
		if (!strcmp(argv[2], "create")) {
			Console::SetupConsole();
			SaveProject();
			return 0;
		} else if (!strcmp(argv[2], "version")) {
			Console::SetupConsole();
			Console::version();
			return 0;
		} else if (!strcmp(argv[2], "protect")) {
			if (argc < 4) {
				LOG(Failed, MODULE_YAP, "Not enough arguments provided\n");
				return 1;
			}
			Console::SetupConsole();
			Console::protect(argv[3], argc > 3 ? argv[4] : NULL);
			return 0;
		}
	}
	if (Data.Project[0] && !LoadProject()) return 1;

	// Setup UI
	if (!Data.bUsingConsole && argc < 4) {
		DEBUG_ONLY(AllocConsole());
		DEBUG_ONLY(Console::SetupConsole());
		if (!BeginGUI()) {
			MessageBox(NULL, "Failed to create GUI!", NULL, MB_ICONERROR | MB_OK);
			return 1;
		}
	}
	return 0;
}

// Actually does the obfuscation
DWORD WINAPI Begin(void* args) {
	// Prevent it from running twice
	if (Data.bRunning)
		return 1;
	Data.bRunning = true;
	LOG(Info, MODULE_YAP, "Starting YAP\n");

	Options_t OptionsBackup = Options;

	// Reassembler
	if (Options.Reassembly.bEnabled) {
		LOG(Info, MODULE_YAP, "Starting reassembler\n");

		// Disassemble
		if (!pAssembly->Disassemble()) {
			Modal("Disassembly failed", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Disassembly failed\n");
			goto th_exit;
		}

		// Analyze
		if (!pAssembly->Analyze()) {
			Modal("Asm analysis failed", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Asm analysis failed\n");
			goto th_exit;
		}

		// Dump disassembly
#ifdef _DEBUG
#ifdef ENABLE_DUMPING
		if (Options.Debug.bDumpAsm) {
			HANDLE hDumped = CreateFile("YAP.dump.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			char buf[512];
			ZydisFormatter Formatter;
			ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);
			Vector<AsmSection> Sections = pAssembly->GetSections();
			for (DWORD SecIndex = 0, n = Sections.Size(); SecIndex < n; SecIndex++) {
				Vector<Line>* Lines = Sections[SecIndex].Lines;
				for (size_t i = 0, j = Lines->Size(); i < j; i++) {
					Line line = Lines->At(i);
					int n = 0;
					switch (line.Type) {
					case Decoded:
						n = snprintf(buf, 512, "%8.8s:%p\t", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA);
						ZydisFormatterFormatInstruction(&Formatter, &line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, &buf[n], 512 - n, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA, NULL);
						n = lstrlenA(buf);
						buf[n] = '\n';
						n++;
						buf[n] = 0;
						break;
					case Embed:
						n = snprintf(buf, 512, "%8.8s:%p\tData %#x\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA, line.Embed.Size);
						break;
					case Padding:
						n = snprintf(buf, 512, "%8.8s:%p\tPadding %#x\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA, line.Padding.Size);
						break;
					case JumpTable:
						n = snprintf(buf, 512, "%8.8s:%p\tcase 0x%p\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA, pAssembly->NTHeaders.OptionalHeader.ImageBase + ((line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value));
						break;
					case Pointer:
						n = snprintf(buf, 512, "%8.8s:%p\tPtr 0x%p\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->NTHeaders.OptionalHeader.ImageBase + line.OldRVA, (line.Pointer.IsAbs ? line.Pointer.Abs : pAssembly->NTHeaders.OptionalHeader.ImageBase + line.Pointer.RVA));
					default:
						break;
					}
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
			CloseHandle(hDumped);
		}
#endif

		HANDLE hDumped = NULL;
		if (Options.Debug.bDumpFunctions) {
			hDumped = CreateFile("YAP.functions.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			char buf[512];
			for (int i = 0; i < pAssembly->GetDisassembledFunctionRanges().Size(); i++) {
				WriteFile(hDumped, "------------\n", 13, NULL, NULL);
				for (int j = 0; j < pAssembly->GetDisassembledFunctionRanges()[i].Entries.Size(); j++) {
					int n = snprintf(buf, 512, "%08lx: %08lx -> %08lx\n", pAssembly->GetDisassembledFunctionRanges()[i].Entries[j], pAssembly->GetDisassembledFunctionRanges()[i].dwStart, pAssembly->GetDisassembledFunctionRanges()[i].dwStart + pAssembly->GetDisassembledFunctionRanges()[i].dwSize);
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
		}
#endif

		// Modify
		if (Options.Reassembly.bStrip && !pAssembly->Strip()) {
			Modal("Failed to strip PE", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Failed to strip PE\n");
			goto th_exit;
		}
		if (Options.Reassembly.bRemoveData) {
			pAssembly->CleanHeaders();
		}

		// Virtualize
		if (Options.VM.bEnabled && !Virtualize(pAssembly)) {
			Modal("Failed to virtualize PE", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Failed to virtualize PE\n");
			goto th_exit;
		}

		// Assemble
		if (!pAssembly->Assemble()) {
			Modal("Assembly failed", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Assembly failed\n");
			goto th_exit;
		}

#ifdef _DEBUG
		if (Options.Debug.bDumpFunctions) {
			WriteFile(hDumped, "\n\n\n", 3, NULL, NULL);
			char buf[512];
			for (int i = 0; i < pAssembly->GetDisassembledFunctionRanges().Size(); i++) {
				WriteFile(hDumped, "------------\n", 13, NULL, NULL);
				for (int j = 0; j < pAssembly->GetDisassembledFunctionRanges()[i].Entries.Size(); j++) {
					int n = snprintf(buf, 512, "%08lx: %08lx -> %08lx\n", pAssembly->GetDisassembledFunctionRanges()[i].Entries[j], pAssembly->GetDisassembledFunctionRanges()[i].dwStart, pAssembly->GetDisassembledFunctionRanges()[i].dwStart + pAssembly->GetDisassembledFunctionRanges()[i].dwSize);
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
			CloseHandle(hDumped);
		}
#endif

		// Modify again
		if (Options.Reassembly.bStripDOSStub) {
			pAssembly->StripDosStub();
			pAssembly->FixHeaders();
		}
		if (Options.Reassembly.Rebase) {
			pAssembly->RebaseImage(Options.Reassembly.Rebase);
		}
	}

	// Pack
	if (Options.Packing.bEnabled) {
		LOG(Info, MODULE_YAP, "Starting packer\n");
		Asm* pPacked = new Asm();
		pPacked->Status = Normal;
		if (!Pack(pAssembly, pPacked)) {
			Modal("Failed to pack PE", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Packer failed\n");
			delete pPacked;
			goto th_exit;
		}
		delete pAssembly;
		pAssembly = pPacked;
	}

	// Save file
	LOG(Success, MODULE_YAP, "All modules passed\n");
	if (Data.hWnd) {
		do {
			while (!OpenFileDialogue(Data.SaveFileName, MAX_PATH, "Binaries\0*.exe;*.dll;*.sys\0All Files\0*.*\0", NULL, true)) {
				if (Modal("Failed to get save file name", "Error", MB_RETRYCANCEL | MB_ICONERROR) == IDCANCEL) {
					Data.bUserCancelled = true;
					break;
				}
			}
			if (!pAssembly->ProduceBinary(Data.SaveFileName)) {
				Modal("Failed to save file", "Error", MB_OK | MB_ICONERROR);
				LOG(Failed, MODULE_YAP, "Failed to save file\n");
				goto th_exit;
			} else {
				break;
			}
		} while (!Data.bUserCancelled);
		if (Data.bUserCancelled) {
			LOG(Info, MODULE_YAP, "User cancelled\n");
		} else {
			LOG(Info_Extended, MODULE_YAP, "Saved to: %s\n", Data.SaveFileName);
		}
	} else {
		if (!pAssembly->ProduceBinary(reinterpret_cast<char*>(args))) {
			Modal("Failed to save file", "Error", MB_OK | MB_ICONERROR);
			LOG(Failed, MODULE_YAP, "Failed to save file\n");
		} else {
			LOG(Info_Extended, MODULE_YAP, "Save to: %s\n", reinterpret_cast<char*>(args));
		}
	}

th_exit:
	Options = OptionsBackup;
	LOG(Info, MODULE_YAP, "Ending YAP\n");
	Data.bRunning = false;
	delete pAssembly;
	pAssembly = NULL;
	return 0;
}

// Crash handler
Vector<MODULEENTRY32> Modules;
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
		LOG(Info_Extended, MODULE_YAP, "Address: 0x%p\n", pExceptionRecord->ExceptionAddress);
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

	DEBUG_EVENT event = { 0 };
	MODULEENTRY32 entry = { 0 };
	entry.dwSize = sizeof(MODULEENTRY32);
	CONTEXT context;
	context.ContextFlags = CONTEXT_AMD64;
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
				HANDLE hHand = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, event.dwThreadId);
				if (!hHand) {
					LOG(Warning, MODULE_YAP, "Failed to open crashed thread (%d)\n", GetLastError());
				} else if (SuspendThread(hHand) == _UI32_MAX) {
					LOG(Warning, MODULE_YAP, "Failed to suspend thread (%d)\n", GetLastError());
				} else if (!GetThreadContext(hHand, &context)) {
					LOG(Warning, MODULE_YAP, "Failed to get thread context (%d)\n", GetLastError());
				} else {
					// This isnt working, I dont know why
					LOG(Info_Extended, MODULE_YAP, "--- CONTEXT ---\n");
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
					ResumeThread(hHand);
				}
				CloseHandle(hHand);

				// Log list of loaded modules
				Modules.Release();
				do {
					hHand = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
				} while (hHand == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);
				if (hHand == INVALID_HANDLE_VALUE) {
					LOG(Warning, MODULE_YAP, "Could not get list of modules (%d)\n", GetLastError());
				} else {
					LOG(Info_Extended, MODULE_YAP, "--- MODULES ---\n");
					Module32First(hHand, &entry);
					do {
						Modules.Push(entry);
						LOG(Info_Extended, MODULE_YAP, "%s: \t0x%p -> 0x%p\n", entry.szModule, entry.modBaseAddr, entry.modBaseAddr + entry.modBaseSize);
					} while (Module32Next(hHand, &entry));
				}

				// Log exceptions
				LOG(Info_Extended, MODULE_YAP, "--- RECORD(S) ---\n");
				LogExceptionRecord(&event.u.Exception.ExceptionRecord);
				LOG(Info_Extended, MODULE_YAP, "----- End of exception -----\n\n\n\n");
			}
			ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
		}
	}
	DebugActiveProcessStop(dwParentId);
	exit(0);
}

void Console::help(char* name) {
	LOG(Nothing, MODULE_YAP, "Usage: %s PROJECT COMMAND\n\n", name);

	LOG(Nothing, MODULE_YAP, "COMMANDS\n");
	LOG(Nothing, MODULE_YAP, "\tcreate\t\t\t\tCreate project\n");
	LOG(Nothing, MODULE_YAP, "\tversion\t\t\t\tGet version of project\n");
	LOG(Nothing, MODULE_YAP, "\tprotect INPUT [OUTPUT]\t\tProtect a file\n\n");

	LOG(Nothing, MODULE_YAP, "ALTERNATIVE COMMANDS\n");
	LOG(Nothing, MODULE_YAP, "%s --version\tGet build info\n", name);
	LOG(Nothing, MODULE_YAP, "%s --help\tGet this help menu\n", name);
}

void Console::buildversion() {
	LOG(Nothing, MODULE_YAP, "YAP: " __YAP_VERSION__ "\n");
	LOG(Nothing, MODULE_YAP, "ImGui: " IMGUI_VERSION "\n");
	LOG(Nothing, MODULE_YAP, "Zydis: %d.%d.%d\n", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
	LOG(Nothing, MODULE_YAP, "AsmJit: %d.%d.%d\n", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
	LOG(Nothing, MODULE_YAP, "GLFW: %s\n", glfwGetVersionString());
	LOG(Nothing, MODULE_YAP, "OpenGL: %s\n", glGetString(GL_VERSION));
	LOG(Nothing, MODULE_YAP, "Build: " __YAP_BUILD__ "\n");
	LOG(Nothing, MODULE_YAP, "Build Time: " __DATE__ " " __TIME__ "\n");
}

void Console::version() {
	HANDLE hFile = CreateFileA(Data.Project, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	BYTE Sig[3] = { 0 };
	DWORD Ver = 0;

	// Check if opened
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		LOG(Failed, MODULE_YAP, "Could not open file %s (%d)\n", Data.Project, GetLastError());
		return;
	}

	// Read signature
	ReadFile(hFile, Sig, 3, NULL, NULL);
	if (memcmp(Sig, "YAP", 3)) {
		LOG(Failed, MODULE_YAP, "%s is not a YAP project\n", Data.Project);
	} else {
		// Read version
		ReadFile(hFile, &Ver, sizeof(DWORD), NULL, NULL);
		LOG(Nothing, MODULE_YAP, "%d.%d.%d %s\n", Ver & __YAP_VERSION_MASK_MAJOR__, (Ver & __YAP_VERSION_MASK_MINOR__) >> 8, (Ver & __YAP_VERSION_MASK_PATCH__) >> 16, (Ver & __YAP_VERSION_MASK_DEBUG__) ? "DEBUG" : "RELEASE");
	}

	CloseHandle(hFile);
}

// Idk improve this maybe
void Console::protect(char* input, char* output) {
	if (strlen(input) + 1 > MAX_PATH || (output && strlen(output) + 1 > MAX_PATH)) {
		LOG(Failed, MODULE_YAP, "Cannot handle files with names longer than MAX_PATH characters (%d bytes)!\n", MAX_PATH);
		return;
	}
	// Load project
	if (!LoadProject()) return;

	// Output name
	char TrueOutput[MAX_PATH] = { 0 };
	if (output) {
		strcpy_s(TrueOutput, output);
	} else {
		int InputLen = strlen(input);
		strcpy_s(TrueOutput, input);
		uint16_t i = InputLen - 1;
		for (; i > 0; i--) {
			if (TrueOutput[i] == '.') break;
		}
		if (i > InputLen || InputLen + 7 > MAX_PATH) {
			LOG(Failed, MODULE_YAP, "Failed to set output name!\n");
			return;
		}
		memmove(&TrueOutput[i + 7], &TrueOutput[i], InputLen + 1 - i);
		memcpy(&TrueOutput[i], "_yapped", 7);
	}

	// Run
	pAssembly = new Asm(input);
	if (pAssembly->Status) {
		LOG(Failed, MODULE_YAP, "Failed to parse binary (%d)\n", pAssembly->Status);
		delete pAssembly;
		pAssembly = NULL;
		return;
	}
	Begin(TrueOutput);
}

void Console::SetupConsole() {
	if (AttachConsole(ATTACH_PARENT_PROCESS) || GetLastError() == ERROR_ACCESS_DENIED) {
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		Data.bUsingConsole = true;
		if (!SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
			LOG(Warning, MODULE_YAP, "Colors wont work, terminal output will be ugly af\n");
		}
	} else {
		LOG(Failed, MODULE_YAP, "Failed to attach to console (%d)\n", GetLastError());
	}
}

void LOG(LoggingLevel_t level, char* mod, char* str, ...) {
	va_list args;
	char buffer[MAX_PATH];
	va_start(args, str);
	vsnprintf(buffer, sizeof(buffer), str, args);
	va_end(args);
	if (Data.bUsingConsole) {
		if (level) {
			switch (level) {
			case Failed:
				WriteConsoleA(hStdOut, LOG_ERROR "[", sizeof(LOG_ERROR), NULL, NULL);
				break;
			case Success:
				WriteConsoleA(hStdOut, LOG_SUCCESS "[", sizeof(LOG_SUCCESS), NULL, NULL);
				break;
			case Warning:
				WriteConsoleA(hStdOut, LOG_WARNING "[", sizeof(LOG_WARNING), NULL, NULL);
				break;
			case Info:
				WriteConsoleA(hStdOut, LOG_INFO "[", sizeof(LOG_INFO), NULL, NULL);
				break;
			case Info_Extended:
				WriteConsoleA(hStdOut, LOG_INFO_EXTRA "[", sizeof(LOG_INFO_EXTRA), NULL, NULL);
			}
			WriteConsoleA(hStdOut, mod, strlen(mod), NULL, NULL);
			WriteConsoleA(hStdOut, "]: \t", 4, NULL, NULL);
		}
		WriteConsoleA(hStdOut, buffer, lstrlenA(buffer), NULL, NULL);
	}

	if (hLogFile) {
		if (level) {
			switch (level) {
			case Failed:
				WriteFile(hLogFile, "[-] [", 5, NULL, NULL);
				break;
			case Success:
				WriteFile(hLogFile, "[+] [", 5, NULL, NULL);
				break;
			case Warning:
				WriteFile(hLogFile, "[*] [", 5, NULL, NULL);
				break;
			case Info:
				WriteFile(hLogFile, "[?] [", 5, NULL, NULL);
				break;
			case Info_Extended:
				WriteFile(hLogFile, "[>] [", 5, NULL, NULL);
			}
			WriteFile(hLogFile, mod, strlen(mod), NULL, NULL);
			WriteFile(hLogFile, "]: \t", 4, NULL, NULL);
		}
		WriteFile(hLogFile, buffer, strlen(buffer), NULL, NULL);
	}
}