#include <Windows.h>

int main() {
	HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, "YAP_Test");
	if (hEvent) {
		SetEvent(hEvent);
	} else {
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Failed to set event!\n", 21, NULL, NULL);
	}
	Sleep(INFINITE);
	return 0;
}