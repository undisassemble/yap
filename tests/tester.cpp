#include <Windows.h>
#include <stdio.h>

// Set this to the path to the YAP executable to be tested
#define PATH_YAP "../bin/Debug/YAP.exe"

// Set this to the max wait time for YAP and for the protected executable (ms), or INFINITE
#define WAIT_TIME_YAP 60000
#define WAIT_TIME_PROT 15000

// Logging stuff
#define LOG_SUCCESS "\x1B[32m[+]\x1B[39m "
#define LOG_INFO "\x1B[36m[?]\x1B[39m "
#define LOG_INFO_EXTRA  "\x1B[36m[>]\x1B[39m "
#define LOG_WARNING "\x1B[33m[*]\x1B[39m "
#define LOG_ERROR "\x1B[31m[-]\x1B[39m "

// Paths to tests
// Contents of each folder should be: in.exe (test app that sets event signal), p.yaproj (test config)
const char* paths[] = {
	"packer/0",
	"packer/1",
	"packer/2",
	"packer/3",
	"packer/4",
	"packer/5",
	"packer/6",
	"packer/7",
	"reasm/0",
	"combo/0",
	"combo/1",
	"combo/2",
	"combo/3",
};

DWORD WINAPI SpinnerThread(char* name) {
	int time = 0;
	while (1) {
		printf("\r| %s... (%d)", name, time / 1000);
		Sleep(100);
		time += 100;
		printf("\r/ %s... (%d)", name, time / 1000);
		Sleep(100);
		time += 100;
		printf("\r- %s... (%d)", name, time / 1000);
		Sleep(100);
		time += 100;
		printf("\r\\ %s... (%d)", name, time / 1000);
		Sleep(100);
		time += 100;
	}
	return 0;
}

int main() {
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
	HANDLE hEvent = CreateEventExA(NULL, "YAP_Test", CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | EVENT_MODIFY_STATE);
	printf("\x1B[?25l");
	if (!hEvent) {
		printf(LOG_ERROR "Failed to create event: %d\n", GetLastError());
		Sleep(INFINITE);
		return 1;
	}
	printf(LOG_INFO_EXTRA "Please continue to use computer to pass activity checks!\n\n");
	Sleep(1500);
	printf(LOG_INFO "Beginning tests\n");
	char temp[MAX_PATH * 3] = { 0 };
	int failed_yap = 0;
	int failed_run = 0;
	int passed = 0;
	
	for (int i = 0; i < sizeof(paths) / sizeof(char*); i++) {
		// Protect
		DeleteFileA("temp.exe");
		if (strlen(PATH_YAP) + strlen(paths[i]) + 37 > MAX_PATH * 3) {
			printf(LOG_ERROR "Name too long\n");
			continue;
		}
		strcpy(temp, "\"" PATH_YAP "\" ");
		strcat(temp, paths[i]);
		strcat(temp, "/p.yaproj protect ");
		strcat(temp, paths[i]);
		strcat(temp, "/in.exe temp.exe");
		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFOA si = { 0 };
		si.cb = sizeof(STARTUPINFOA);
		if (!CreateProcessA(NULL, temp, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			printf(LOG_ERROR "Failed to start YAP (%d)\n", GetLastError());
			continue;
		}
		WaitForSingleObject(pi.hProcess, WAIT_TIME_YAP);
		DWORD status = 0;
		GetExitCodeProcess(pi.hProcess, &status);
		if (status == STILL_ACTIVE) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			printf(LOG_WARNING "YAP did not finish in time\n");
			failed_yap++;
			continue;
		}
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		
		// Test output
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFOA));
		si.cb = sizeof(STARTUPINFOA);
		ResetEvent(hEvent);
		if (!CreateProcessA("temp.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
			if (GetLastError() == ERROR_FILE_NOT_FOUND) failed_yap++;
			printf(LOG_ERROR "Failed to start protected executable (%d)\n", GetLastError());
			strcpy(temp, paths[i]);
			strcat(temp, "/Yap.log.txt");
			CopyFile("Yap.log.txt", temp, FALSE);
			continue;
		}
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SpinnerThread, (LPVOID)paths[i], 0, NULL);
		HANDLE Events[2] = { hEvent, pi.hProcess };
		if (WaitForMultipleObjects(2, Events, FALSE, WAIT_TIME_PROT) == WAIT_OBJECT_0) {
			TerminateProcess(pi.hProcess, 0);
			TerminateThread(hThread, 0);
			printf("\r" LOG_SUCCESS "Success: %s\n", paths[i]);
			passed++;
		} else {
			TerminateProcess(pi.hProcess, 0);
			TerminateThread(hThread, 0);
			printf("\r" LOG_WARNING "%s crashed/froze, or wait function failed\n", paths[i]);
			strcpy(temp, paths[i]);
			strcat(temp, "/Yap.log.txt");
			CopyFile("Yap.log.txt", temp, FALSE);
			strcpy(temp, paths[i]);
			strcat(temp, "/out.exe");
			CopyFile("temp.exe", temp, FALSE);
			failed_run++;
		}
		CloseHandle(hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	
	if (!DeleteFileA("Yap.log.txt")) {
		printf(LOG_WARNING "Failed to delete files (%d)\n", GetLastError());
	}
	DeleteFileA("temp.exe");
	printf(LOG_INFO "Finished tests\n");
	printf(LOG_INFO_EXTRA "Passed: %d, Failed outputs: %d, Failed during protection: %d\n", passed, failed_run, failed_yap);
	Sleep(INFINITE);
	return 0;
}