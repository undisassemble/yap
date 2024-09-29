#include "util.h"
#include "asm.hpp"
#include "pe.hpp"
#include "packer.hpp"
#include "gui.hpp"
#include "font.hpp"
#include <TlHelp32.h>
#include <imgui.h>
#include <imgui_internal.h>
#include <Psapi.h>
#include <time.h>

// Forward declares
DWORD WINAPI Begin(void* args);
DWORD WINAPI ParsePE(void* args);
bool OpenFileDialogue(_Out_ char* pOut, _In_ size_t szOut, _In_ char* pFilter, _Out_opt_ WORD* pFileNameOffset, _In_ bool bSaveTo);
namespace Console {
	void help();
	void version();
}

Options_t Options;
Data_t Data;
HANDLE hLogFile = NULL;
HANDLE hStdOut = NULL;
Asm* pAssembly = NULL;

// Main function
int main(int argc, char** argv) {
	// General setup
	srand(time(NULL));

	// Load settings
	HANDLE hSettings = CreateFileA("yap.config", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hSettings != INVALID_HANDLE_VALUE) {
		ReadFile(hSettings, &Options.Settings, sizeof(Options.Settings), NULL, NULL);
	}
	CloseHandle(hSettings);

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
		ImGui::CreateContext();
		ImGuiIO& imIO = ImGui::GetIO();
		imIO.ConfigFlags = ImGuiConfigFlags_NavEnableKeyboard;
		imIO.IniFilename = NULL;
		ApplyImGuiTheme();

		// RobotoFont from ImGui
		imIO.Fonts->AddFontFromMemoryCompressedTTF(RobotoFont_compressed_data, RobotoFont_compressed_size, 16.f);

		// Handle files dropped on top of executable
		if (argc == 2) {
			pAssembly = new Asm(argv[1]);
			if (pAssembly->GetStatus()) {
				MessageBoxA(NULL, "Could not parse binary!", NULL, MB_OK | MB_ICONERROR);
			} else {
				Data.bParsing = true;
				CreateThread(0, 0, ParsePE, 0, 0, 0);
			}
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
			Console::help();
			return 1;
		}

		// Parse arguments
		for (int i = 1; i < argc; i++) {

			// --help, -h
			if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
				Console::help();
				return 0;
			}

			// --version, -v
			else if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-v")) {
				Console::version();
				return 0;
			}

			// --packer=, --packer:
			else if (!memcmp(argv[i], "--packer=", 9) || !memcmp(argv[i], "--packer:", 9)) {
				
			}
		}

		// Begin
		CreateThread(0, 0, Begin, 0, 0, 0);
	}
	return 0;
}

// Actually does the obfuscation
DWORD WINAPI Begin(void* args) {
	// Prevent it from running twice
	if (Data.bRunning)
		return 1;
	
	Data.bRunning = true;
	hLogFile = CreateFile("Yap.log.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	LOG(Info, MODULE_YAP, "Starting Yap\n");

	// Reassembler
	if (Options.Reassembly.bEnabled) {
		LOG(Info, MODULE_YAP, "Starting reassembler\n");

		// Disassemble
		if (!pAssembly->Disassemble()) {
			LOG(Failed, MODULE_YAP, "Disassembly failed!\n");
			goto th_exit;
		}

		// Dump disassembly
#ifdef _DEBUG
		if (Options.Debug.bDumpAsm) {
			HANDLE hDumped = CreateFile("Yap.dump.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			char buf[512];
			ZydisFormatter Formatter;
			ZydisFormatterInit(&Formatter, ZYDIS_FORMATTER_STYLE_INTEL);
			Vector<AsmSection> Sections = pAssembly->GetSections();
			for (DWORD SecIndex = 0, n = Sections.Size(); SecIndex < n; SecIndex++) {
				Vector<Line>* Lines = Sections.At(SecIndex).Lines;
				for (size_t i = 0, j = Lines->Size(); i < j; i++) {
					Line line = Lines->At(i);
					int n = 0;
					switch (line.Type) {
					case Decoded:
						n = snprintf(buf, 512, "%8.8s:%p\t", pAssembly->GetSectionHeader(SecIndex)->Name, pAssembly->GetBaseAddress() + line.OldRVA);
						ZydisFormatterFormatInstruction(&Formatter, &line.Decoded.Instruction, line.Decoded.Operands, line.Decoded.Instruction.operand_count_visible, &buf[n], 512 - n, pAssembly->GetBaseAddress() + line.OldRVA, NULL);
						n = lstrlenA(buf);
						buf[n] = '\n';
						n++;
						buf[n] = 0;
						break;
					case Embed:
						n = snprintf(buf, 512, "%8.8s:%p\tData %#x\n", pAssembly->GetSectionHeader(SecIndex)->Name, pAssembly->GetBaseAddress() + line.OldRVA, line.Embed.Size);
						break;
					case Padding:
						n = snprintf(buf, 512, "%8.8s:%p\tPadding %#x\n", pAssembly->GetSectionHeader(SecIndex)->Name, pAssembly->GetBaseAddress() + line.OldRVA, line.Padding.Size);
						break;
					case JumpTable:
						n = snprintf(buf, 512, "%8.8s:%p\tcase 0x%p\n", pAssembly->GetSectionHeader(SecIndex)->Name, pAssembly->GetBaseAddress() + line.OldRVA, pAssembly->GetBaseAddress() + ((line.bRelative ? line.JumpTable.Base : 0) + line.JumpTable.Value));
						break;
					case Pointer:
						n = snprintf(buf, 512, "%8.8s:%p\tPtr 0x%p\n", pAssembly->GetSectionHeader(SecIndex)->Name, pAssembly->GetBaseAddress() + line.OldRVA, (line.Pointer.IsAbs ? line.Pointer.Abs : pAssembly->GetBaseAddress() + line.Pointer.RVA));
					case Encoded:
						break;
					}
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
	}

	// Pack
	if (Options.Packing.bEnabled) {
		LOG(Info, MODULE_YAP, "Starting packer\n");
		PackerOptions PackOpt = { 0 };
		PackOpt.Message = Options.Packing.Message[0] ? Options.Packing.Message : NULL;
		PackOpt.bVM = Options.VM.bEnabled;
		for (int i = 0, n = Options.VM.VMFuncs.Size(); i < n; i++) {
			PackOpt.VMFuncs.Push(Data.PEFunctions.At(Options.VM.VMFuncs.At(i) - 1).u64Address - pAssembly->GetBaseAddress());
		}
		if (Options.Packing.bEnableMasquerade) {
			PackOpt.sMasqueradeAs = Options.Packing.Masquerade;
		}
		Asm* pPacked = new Asm();
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

th_exit:
	LOG(Info, MODULE_YAP, "Ending Yap\n");
	CloseHandle(hLogFile);
	Data.bRunning = false;
	delete pAssembly;
	return 0;
}

void Console::help() {

}

void Console::version() {
	LOG(Nothing, MODULE_YAP, "Yap Version: " __YAP_VERSION__ "\n");
	LOG(Nothing, MODULE_YAP, "Build: " __YAP_BUILD__ "\n");
	LOG(Nothing, MODULE_YAP, "Build Time: " __DATE__ " " __TIME__ "\n");
	LOG(Nothing, MODULE_YAP, "ImGui Version: " IMGUI_VERSION "\n");
	LOG(Nothing, MODULE_YAP, "Zydis Version: %d.%d.%d\n", ZYDIS_VERSION_MAJOR(ZYDIS_VERSION), ZYDIS_VERSION_MINOR(ZYDIS_VERSION), ZYDIS_VERSION_PATCH(ZYDIS_VERSION));
	LOG(Nothing, MODULE_YAP, "AsmJit Version: %d.%d.%d\n", ASMJIT_LIBRARY_VERSION_MAJOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_MINOR(ASMJIT_LIBRARY_VERSION), ASMJIT_LIBRARY_VERSION_PATCH(ASMJIT_LIBRARY_VERSION));
}