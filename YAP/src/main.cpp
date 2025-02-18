#include "util.hpp"
#include "asm.hpp"
#include "pe.hpp"
#include "packer.hpp"
#include "gui.hpp"
#include <time.h>
#include <stdarg.h>
#include <GLFW/glfw3.h>

// Forward declares
DWORD WINAPI Begin(void* args);
namespace Console {
	void help(char* name);
	void buildversion();
	void version();
	void protect(char* input, char* output = NULL);
	void SetupConsole();
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
	hLogFile = CreateFile("yap.log.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hLogFile || hLogFile == INVALID_HANDLE_VALUE) {
		LOG(Failed, MODULE_YAP, "Failed to open logging file (%d)\n", GetLastError());
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
	strcpy_s(Data.Project, argv[1]);
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

	// Select optimization mode
	bool bResetOptimizations = false;

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
					default:
						break;
					}
					WriteFile(hDumped, buf, n, NULL, NULL);
				}
			}
			CloseHandle(hDumped);
		}

		HANDLE hDumped = NULL;
		if (Options.Debug.bDumpFunctions) {
			hDumped = CreateFile("YAP.functions.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			char buf[512];
			for (int i = 0; i < pAssembly->GetDisassembledFunctionRanges().Size(); i++) {
				WriteFile(hDumped, "------------\n", 13, NULL, NULL);
				for (int j = 0; j < pAssembly->GetDisassembledFunctionRanges()[i].Entries.Size(); j++) {
					int n = snprintf(buf, 512, "%08x: %08x -> %08x\n", pAssembly->GetDisassembledFunctionRanges()[i].Entries[j], pAssembly->GetDisassembledFunctionRanges()[i].dwStart, pAssembly->GetDisassembledFunctionRanges()[i].dwStart + pAssembly->GetDisassembledFunctionRanges()[i].dwSize);
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
					int n = snprintf(buf, 512, "%08x: %08x -> %08x\n", pAssembly->GetDisassembledFunctionRanges()[i].Entries[j], pAssembly->GetDisassembledFunctionRanges()[i].dwStart, pAssembly->GetDisassembledFunctionRanges()[i].dwStart + pAssembly->GetDisassembledFunctionRanges()[i].dwSize);
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
	return 0;
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
	// LOG(Nothing, MODULE_YAP, "OpenGL: %s\n", glGetString(GL_VERSION));
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
	delete pAssembly;
	pAssembly = NULL;
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