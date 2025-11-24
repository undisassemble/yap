#include <windows.h>
#include <stdio.h>

#define EXPORT __declspec(dllexport)

EXPORT void SwitchShort(int in);
EXPORT void SwitchLong(int in);
EXPORT void SwitchWideShort(int in);
EXPORT void SwitchWideLong(int in);

int main() {
	SwitchShort(2);
	SwitchLong(7);
	SwitchWideShort(5);
	SwitchWideLong(3);
	return 0;
}

EXPORT void SwitchWideShort(int in) {
	switch (in) {
	case 0:
		printf("Switch wide case 0\n");
		break;
	case 400:
		puts("Switch wide case 400\n");
		break;
	case 1200:
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Switch wide case 1200\n", 22, NULL, NULL);
		break;
	case 5320:
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"Switch wide case thingy\n", 24, NULL, NULL);
		__fallthrough;
	case 7420:
		exit(0);
		break;
	case 8953:
		SwitchWideShort(0);
		break;
	default:
		SwitchWideLong(in / 3);
	}
}

EXPORT void SwitchWideLong(int in) {
	switch (in) {
	case 0:
		printf("Switch wide case 0\n");
		break;
	case 400:
		puts("Switch wide case 400\n");
		break;
	case 1200:
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Switch wide case 1200\n", 22, NULL, NULL);
		break;
	case 5320:
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"Switch wide case thingy\n", 24, NULL, NULL);
		__fallthrough;
	case 7420:
		exit(0);
		break;
	case 8953:
		SwitchWideLong(0);
		break;
	case 9350:
		printf("Do things here\n");
		break;
	case 10653:
		printf("Do more things here\n");
		break;
	case 11485:
		printf("Do even more things here\n");
		__fallthrough;
	case 12698:
		printf("Get this, do even MORE things here\n");
		break;
	case 13785:
		printf("Razzle dazzle\n");
		break;
	case 14387:
		printf("Stuff\n");
		break;
	case 15542:
		SwitchLong(12);
		break;
	case 16325:
		SwitchShort(5);
		break;
	case 17533:
		printf("Im gonna steal from SwitchLong rq brb\n");
		break;
	case 18237:
		puts("AAAAAAAAAAAH\n");
		break;
	case 19237:
		puts("OWJEFOOLEJF\n");
		break;
	case 20123:
		puts("blah blah blah blah blah blah blah\n");
		break;
	case 22520:
		puts("Random shit\n");
		break;
	case 23462:
		puts("Even more random shit\n");
		break;
	case 24548:
		puts("Optimizations better not fuck this up\n");
		__fallthrough;
	case 25124:
		puts("wewewewewewewewewewe\n");
		break;
	case 26853:
		puts("did you know\n");
		break;
	case 31531:
		puts("bye bye\n");
		break;
	case 32264:
		puts("jk lol still some more\n");
		__fallthrough;
	case 34523:
		puts("bye bye fr now\n");
		break;
	case 35634:
		puts("nope still lying\n");
		break;
	case 36314:
		puts("ok actually bye bye this time\n");
		break;
	default:
		SwitchWideShort(in / 3);
	}
}

EXPORT void SwitchLong(int in) {
	switch (in) {
	case 0:
		printf("Switch long case 0\n");
		break;
	case 1:
		puts("Switch long case 1\n");
		break;
	case 3:
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Switch long case 3\n", 19, NULL, NULL);
		break;
	case 4:
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), L"Switch long case 4\n", 19, NULL, NULL);
		break;
	case 5:
		exit(3);
		break;
	case 6:
		puts("Switch long ewoijf\n");
		__fallthrough;
	case 8:
		puts("Switch long fews\n");
		break;
	case 12:
		puts("Switch long ewoijf\n");
		break;
	case 11:
		puts("Switch long wasdefaw\n");
		break;
	case 13:
		puts("Switch long faiuywersdifhalwh\n");
		break;
	case 10:
		puts("Switch long ewoaj\n");
		break;
	case 9:
		puts("Switch whfoeiuahiweufhawie\n");
		break;
	case 15:
		puts("AAAAAAAAAAAH\n");
		break;
	case 17:
		puts("OWJEFOOLEJF\n");
		break;
	case 20:
		puts("blah blah blah blah blah blah blah\n");
		break;
	case 23:
		puts("Random shit\n");
		break;
	case 22:
		puts("Even more random shit\n");
		break;
	case 25:
		puts("Optimizations better not fuck this up\n");
		__fallthrough;
	case 24:
		puts("wewewewewewewewewewe\n");
		break;
	case 28:
		puts("did you know\n");
		break;
	case 31:
		puts("bye bye\n");
		break;
	case 32:
		puts("jk lol still some more\n");
		__fallthrough;
	case 34:
		puts("bye bye fr now\n");
		break;
	case 35:
		puts("nope still lying\n");
		break;
	case 36:
		puts("ok actually bye bye this time\n");
		break;
	default:
		SwitchWideLong(3 * in + 4);
	}
}

EXPORT void SwitchShort(int in) {
	switch (in) {
	case 0:
		printf("Switch short case 0\n");
		break;
	case 1:
		puts("Switch short case 1\n");
		__fallthrough;
	case 2:
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "Switch short case 2\n", 20, NULL, NULL);
		break;
	case 3:
		SwitchWideShort(3);
		break;
	case 4:
		exit(0);
		break;
	default:
		SwitchLong(in);
	}
}