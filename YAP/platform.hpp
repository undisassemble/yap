#pragma once

// Standard headers
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Linux stuff
#if defined(__linux__)
#include <unistd.h>
#include <pthread.h>
#define __YAP_PLATFORM__ "Linux"
#define LINUX_ONLY(x) x
#define WINDOWS_ONLY(x)

// Missing from WINAPI
#define WINAPI __stdcall
#define _In_
#define _Out_
#define _In_opt_
#define _Out_opt_
#define ZeroMemory(ptr, sz) memset(ptr, 0, sz)
#define MAX_PATH 256
#define MB_OK 0
#define MB_OKCANCEL 1
#define MB_ABORTRETRYIGNORE 2
#define MB_YESNOCANCEL 3
#define MB_YESNO 4
#define MB_RETRYCANCEL 5
#define MB_CANCELTRYCONTINUE 6
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;

// Windows stuff
#elif defined(_WIN64)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <shellapi.h>
#define __YAP_PLATFORM__ "Windows"
#define LINUX_ONLY(x)
#define WINDOWS_ONLY(x) x
#endif

typedef uint64_t QWORD;