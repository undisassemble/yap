#include "util.h"
#include "asm.hpp"
#include "pe.hpp"
#include "packer.hpp"
#include "gui.hpp"
#include <TlHelp32.h>
#include <imgui.h>
#include <imgui_internal.h>
#include <Psapi.h>
#include <time.h>

// Forward declares
DWORD WINAPI Begin(void* args);
namespace Console {
	void help(char* name);
	void buildversion();
	void create(char* project);
	void version(char* project);
	void read(char* project);
	void protect(char* project, char* input, char* output = NULL);
}


Options_t Options;
Settings_t Settings;
Data_t Data;
HANDLE hLogFile = NULL;
HANDLE hStdOut = NULL;
Asm* pAssembly = NULL;

// Main function
int main(int argc, char** argv) {
	// General setup
	srand(time(NULL));
	hLogFile = CreateFile("YAP.log.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hLogFile || hLogFile == INVALID_HANDLE_VALUE) {
		LOG(Failed, MODULE_YAP, "Failed to open logging file: %d\n", GetLastError());
	}
	LoadSettings();

	// Find out if parent process is cmd.exe
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 peEntry = { 0 };
	DWORD dwPID = GetCurrentProcessId();
	peEntry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &peEntry)) {
		do {
			if (peEntry.th32ProcessID == dwPID) break;
		} while (Process32Next(hSnap, &peEntry));
	}
	CloseHandle(hSnap);
	if (peEntry.th32ProcessID == dwPID) {
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, peEntry.th32ParentProcessID);
		char Name[MAX_PATH];
		DWORD szName = MAX_PATH;
		QueryFullProcessImageName(hProc, 0, Name, &szName);
		Data.bUsingConsole = !strcmp(Name, "C:\\Windows\\System32\\cmd.exe");
		CloseHandle(hProc);
	}
	
	// Setup UI (CLI not yet implimented)
	if (!Data.bUsingConsole && argc < 3) {
		RELEASE_ONLY(FreeConsole());
		DEBUG_ONLY(Data.bUsingConsole = true); // Makes the console visible in debug builds
		DEBUG_ONLY(SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING));
		DEBUG_ONLY(hStdOut = GetStdHandle(STD_OUTPUT_HANDLE));
		InitGUI();

		// Handle files dropped on top of executable
		if (argc == 2) {
			strcpy_s(Data.Project, argv[1]);
			LoadProject();
		}

		if (!BeginGUI()) {
			MessageBox(NULL, "Failed to create GUI!", NULL, MB_ICONERROR | MB_OK);
			return 1;
		}
	}

	// Setup console
	else {
		SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

		// Check number of arguments
		if (argc < 2) {
			Console::help(argv[0]);
			return 1;
		}

		// --version and --help
		if (!lstrcmpA(argv[1], "--help") || !lstrcmpA(argv[1], "-h")) {
			Console::help(argv[0]);
			return 0;
		} else if (!lstrcmpA(argv[1], "--version") || !lstrcmpA(argv[1], "-v")) {
			Console::buildversion();
			return 0;
		}

		// Check number of args again
		if (argc < 3) {
			Console::help(argv[0]);
			return 1;
		}
		
		// Dispatch
		if (!lstrcmpA(argv[2], "create")) {
			Console::create(argv[1]);
		} else if (!lstrcmpA(argv[2], "version")) {
			Console::version(argv[1]);
		} else if (!lstrcmpA(argv[2], "read")) {
			Console::read(argv[1]);
		} else if (!lstrcmpA(argv[2], "protect")) {
			if (argc < 4) {
				LOG(Failed, MODULE_YAP, "Not enough arguments for command protect\n");
				return 1;
			}
			Console::protect(argv[1], argv[3], argc > 4 ? argv[4] : NULL);
		} else {
			LOG(Failed, MODULE_YAP, "Unrecognized command: %s\n", argv[2]);
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

	// Select optimization mode
	bool bResetOptimizations = false;

	// Reassembler
	if (Options.Reassembly.bEnabled) {
		LOG(Info, MODULE_YAP, "Starting reassembler\n");

		// Disassemble
		if (!pAssembly->Disassemble()) {
			LOG(Failed, MODULE_YAP, "Disassembly failed!\n");
			goto th_exit;
		}

		// Analyze
		if (!pAssembly->Analyze()) {
			LOG(Failed, MODULE_YAP, "Asm analysis failed!\n");
			goto th_exit;
		}

		// Dump disassembly
#ifdef _DEBUG
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
						n = snprintf(buf, 512, "%8.8s:%p\t", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->GetBaseAddress() + line.OldRVA);
						ZydisFormatterFormatInstruction(&Formatter, &line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, &buf[n], 512 - n, pAssembly->GetBaseAddress() + line.OldRVA, NULL);
						n = lstrlenA(buf);
						buf[n] = '\n';
						n++;
						buf[n] = 0;
						break;
					case Embed:
						n = snprintf(buf, 512, "%8.8s:%p\tData %#x\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->GetBaseAddress() + line.OldRVA, line.Embed.Size);
						break;
					case Padding:
						n = snprintf(buf, 512, "%8.8s:%p\tPadding %#x\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->GetBaseAddress() + line.OldRVA, line.Padding.Size);
						break;
					case JumpTable:
						n = snprintf(buf, 512, "%8.8s:%p\tcase 0x%p\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->GetBaseAddress() + line.OldRVA, pAssembly->GetBaseAddress() + ((line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value));
						break;
					case Pointer:
						n = snprintf(buf, 512, "%8.8s:%p\tPtr 0x%p\n", pAssembly->SectionHeaders[SecIndex].Name, pAssembly->GetBaseAddress() + line.OldRVA, (line.Pointer.IsAbs ? line.Pointer.Abs : pAssembly->GetBaseAddress() + line.Pointer.RVA));
					case Encoded:
						break;
					}
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
			CloseHandle(hDumped);
		}

		if (Options.Debug.bDumpFunctions) {
			HANDLE hDumped = CreateFile("YAP.functions.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			char buf[512];
			for (int i = 0; i < pAssembly->GetDisassembledFunctionRanges().Size(); i++) {
				WriteFile(hDumped, "------------\n", 13, NULL, NULL);
				for (int j = 0; j < pAssembly->GetDisassembledFunctionRanges()[i].Entries.Size(); j++) {
					int n = snprintf(buf, 512, "%08x: %08x -> %08x\n", pAssembly->GetDisassembledFunctionRanges()[i].Entries[j], pAssembly->GetDisassembledFunctionRanges()[i].dwStart, pAssembly->GetDisassembledFunctionRanges()[i].dwStart + pAssembly->GetDisassembledFunctionRanges()[i].dwSize);
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
			CloseHandle(hDumped);
		}
#endif

		// Modify
		if (Options.Reassembly.bStrip && !pAssembly->Strip()) {
			LOG(Failed, MODULE_YAP, "Failed to strip PE\n");
			goto th_exit;
		}
		if (!pAssembly->Mutate()) {
			LOG(Failed, MODULE_YAP, "Failed to mutate PE\n");
			goto th_exit;
		}

		// Virtualize
		if (Options.VM.bEnabled && !Virtualize(pAssembly)) {
			LOG(Failed, MODULE_YAP, "Failed to virtualize PE\n");
			goto th_exit;
		}

		// Fixup
		if (!pAssembly->FixAddresses()) {
			LOG(Failed, MODULE_YAP, "Reassembler failed!\n");
			goto th_exit;
		}

		// Assemble
		if (!pAssembly->Assemble()) {
			LOG(Failed, MODULE_YAP, "Assembly failed!\n");
			goto th_exit;
		}

		// Modify (after assembled)
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
		PackerOptions PackOpt = { 0 };
		PackOpt.Message = Options.Packing.Message[0] ? Options.Packing.Message : NULL;
		PackOpt.bVM = Options.VM.bEnabled;
		for (int i = 0, n = Options.VM.VMFuncs.Size(); i < n; i++) {
			PackOpt.VMFuncs.Push(0);
		}
		if (Options.Packing.bEnableMasquerade) {
			PackOpt.sMasqueradeAs = Options.Packing.Masquerade;
		}
		Asm* pPacked = new Asm();
		pPacked->Status = Normal;
		if (!Pack(pAssembly, PackOpt, pPacked)) {
			LOG(Failed, MODULE_YAP, "Packer failed!\n");
			delete pPacked;
			PackOpt.VMFuncs.Release();
			goto th_exit;
		}
		delete pAssembly;
		pAssembly = pPacked;
		PackOpt.VMFuncs.Release();
	}

	// Save file
	LOG(Success, MODULE_YAP, "All modules passed\n");
	if (Data.hWnd) {
		do {
			Data.bWaitingOnFile = true;
			while (Data.bWaitingOnFile) Sleep(1);
			if (!pAssembly->ProduceBinary(Data.SaveFileName)) {
				LOG(Failed, MODULE_YAP, "Failed to save file!\n");
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
			LOG(Failed, MODULE_YAP, "Failed to save file!\n");
		} else {
			LOG(Info_Extended, MODULE_YAP, "Save to: %s\n", reinterpret_cast<char*>(args));
		}
	}

th_exit:
	Options = OptionsBackup;
	LOG(Info, MODULE_YAP, "Ending YAP\n");
	Data.bRunning = false;
	delete pAssembly;
	return 0;
}

void Console::help(char* name) {
	LOG(Nothing, MODULE_YAP, "Usage: %s PROJECT COMMAND\n\n", name);

	LOG(Nothing, MODULE_YAP, "COMMANDS\n");
	LOG(Nothing, MODULE_YAP, "\tcreate\t\tCreate project\n");
	LOG(Nothing, MODULE_YAP, "\tversion\t\tGet version of project\n");
	LOG(Nothing, MODULE_YAP, "\tread\t\tOutput configuration options from project\n");
	LOG(Nothing, MODULE_YAP, "\tprotect INPUT [OUTPUT]\tProtect a file\n\n");

	LOG(Nothing, MODULE_YAP, "ALTERNATIVE COMMANDS\n");
	LOG(Nothing, MODULE_YAP, "%s --version\tGet build info\n", name);
	LOG(Nothing, MODULE_YAP, "%s --help\tGet this help menu\n", name);
}

void Console::buildversion() {
	LOG(Nothing, MODULE_YAP, "YAP Version: " __YAP_VERSION__ "\n");
	LOG(Nothing, MODULE_YAP, "Build: " __YAP_BUILD__ "\n");
	LOG(Nothing, MODULE_YAP, "Build Time: " __DATE__ " " __TIME__ "\n");
	LOG(Nothing, MODULE_YAP, "ImGui Version: " IMGUI_VERSION "\n");
	LOG(Nothing, MODULE_YAP, "Zydis Version: %d.%d.%d\n", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
	LOG(Nothing, MODULE_YAP, "AsmJit Version: %d.%d.%d\n", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
}

void Console::create(char* project) {
	if (lstrlenA(project) + 1 > MAX_PATH) {
		LOG(Failed, MODULE_YAP, "Cannot handle project files with names longer than MAX_PATH characters (%d bytes)!\n", MAX_PATH);
		return;
	}
	memcpy(Data.Project, project, lstrlenA(project) + 1);
	SaveProject();
}

void Console::version(char* project) {
	HANDLE hFile = CreateFileA(project, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	BYTE Sig[3] = { 0 };
	DWORD Ver = 0;

	// Read signature
	ReadFile(hFile, Sig, 3, NULL, NULL);
	if (memcmp(Sig, "YAP", 3)) {
		LOG(Failed, MODULE_YAP, "%s is not a YAP project\n", project);
	} else {
		// Read version
		ReadFile(hFile, &Ver, sizeof(DWORD), NULL, NULL);
		LOG(Nothing, MODULE_YAP, "%d.%d.%d %s\n", Ver & __YAP_VERSION_MASK_MAJOR__, (Ver & __YAP_VERSION_MASK_MINOR__) >> 8, (Ver & __YAP_VERSION_MASK_PATCH__) >> 16, (Ver & __YAP_VERSION_MASK_DEBUG__) ? "DEBUG" : "RELEASE");
	}

	CloseHandle(hFile);
}

void Console::read(char* project) {
	if (lstrlenA(project) + 1 > MAX_PATH) {
		LOG(Failed, MODULE_YAP, "Cannot handle project files with names longer than MAX_PATH characters (%d bytes)!\n", MAX_PATH);
		return;
	}
	memcpy(Data.Project, project, lstrlenA(project) + 1);
	
	// Load project
	if (!LoadProject()) return;

	LOG(Nothing, MODULE_YAP, "\nOptions for %s\n\n", project);
	// List values
#define LIST(name, type_id) LOG(Nothing, MODULE_YAP, "%s = %" #type_id "\n", #name, name)
	LIST(Options.Packing.bEnabled, d);
	LIST(Options.Packing.bAntiDump, d);
	LIST(Options.Packing.bEnableMasquerade, d);
	LIST(Options.Packing.bNukeHeaders, d);
	LIST(Options.Packing.bMitigateSideloading, d);
	LIST(Options.Packing.bOnlyLoadMicrosoft, d);
	LIST(Options.Packing.bMarkCritical, d);
	LIST(Options.Packing.bAntiDebug, d);
	LIST(Options.Packing.bAntiVM, d);
	LIST(Options.Packing.bAllowHyperV, d);
	LIST(Options.Packing.bAntiSandbox, d);
	LIST(Options.Packing.bHideIAT, d);
	LIST(Options.Packing.bDelayedEntry, d);
	LIST(Options.Packing.bDontCompressRsrc, d);
	LIST(Options.Packing.bDirectSyscalls, d);
	LIST(Options.Packing.bPartialUnpacking, d);
	LIST(Options.Packing.CompressionLevel, d);
	LIST(Options.Packing.Immitate, d);
	LIST(Options.Packing.Masquerade, s);
	LIST(Options.Packing.Message, );
	LIST(Options.Packing.MutationLevel, d);
	LIST(Options.Packing.EncodingCounts, d);
	LIST(Options.VM.bEnabled, d);
	LIST(Options.VM.bVirtEntry, d);
	LIST(Options.Reassembly.bEnabled, d);
	LIST(Options.Reassembly.bStrip, d);
	LIST(Options.Reassembly.bStripDOSStub, d);
	LIST(Options.Reassembly.bSubstitution, d);
	LIST(Options.Reassembly.Rebase, p);
#ifdef _DEBUG
	LIST(Options.Debug.bDumpAsm, d);
	LIST(Options.Debug.bDumpSections, d);
	LIST(Options.Debug.bDumpFunctions, d);
	LIST(Options.Debug.bGenerateBreakpoints, d);    
	LIST(Options.Debug.bGenerateMarks, d);
	LIST(Options.Debug.bDisableRelocations, d);
#endif
#undef LIST

	// List VM funcs
	LOG(Nothing, MODULE_YAP, "\nNum VM funcs: %d\n", Options.VM.VMFuncs.Size());
	for (int i = 0; i < Options.VM.VMFuncs.Size(); i++) {
		LOG(Nothing, MODULE_YAP, "Func %d name: %s\n", i + 1, Options.VM.VMFuncs[i].Name);
		LOG(Nothing, MODULE_YAP, "Remove export of func %d: %d\n", i + 1, Options.VM.VMFuncs[i].bRemoveExport);
	}
}

void Console::protect(char* project, char* input, char* output) {
	if (lstrlenA(project) + 1 > MAX_PATH) {
		LOG(Failed, MODULE_YAP, "Cannot handle project files with names longer than MAX_PATH characters (%d bytes)!\n", MAX_PATH);
		return;
	}
	if (lstrlenA(input) + 1 > MAX_PATH || (output && lstrlenA(output) + 1 > MAX_PATH)) {
		LOG(Failed, MODULE_YAP, "Cannot handle files with names longer than MAX_PATH characters (%d bytes)!\n", MAX_PATH);
		return;
	}
	memcpy(Data.Project, project, lstrlenA(project) + 1);

	// Load project
	if (!LoadProject()) return;

	// Output name
	char TrueOutput[MAX_PATH] = { 0 };
	if (output) {
		memcpy(TrueOutput, output, lstrlenA(output) + 1);
	} else {
		int InputLen = lstrlenA(input);
		memcpy(TrueOutput, input, InputLen + 1);
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

	pAssembly = new Asm(input);
	Begin(TrueOutput);
}