#include "processenv.h"
#include <windows.h>

int main() {
	WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Hello World!\n", 13, NULL, NULL);
	Sleep(500);
	exit(0);
	return 0;
}