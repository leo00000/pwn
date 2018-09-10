// Payload.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

//int CreateProceesByToken(LPSTR lpTokenProcessName, LPSTR lpProcess, LPSTR lpCommand)
//{
//	HANDLE hToken = 0;
//	LPSTR lpName = lpTokenProcessName;
//	HANDLE hProcessSnap = 0;
//	PROCESSENTRY32 pe32 = { 0 };
//	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
//	pe32.dwSize = sizeof(PROCESSENTRY32);
//	for (Process32First(hProcessSnap, &pe32); Process32Next(hProcessSnap, &pe32);)
//	{
//		if (strcmp(_strupr(pe32.szExeFile), _strupr(lpName))) continue;
//		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
//		OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
//		CloseHandle(hProcessSnap);
//	}
//	if (hToken == 0) return 0;
//	STARTUPINFOA si;
//	PROCESS_INFORMATION pi;
//	ZeroMemory(&si, sizeof(STARTUPINFO));
//	si.cb = sizeof(STARTUPINFO);
//	si.lpDesktop = "winsta0\\default";
//	si.dwFlags = STARTF_USESHOWWINDOW;
//	si.wShowWindow = SW_SHOW;
//	return CreateProcessAsUserA(hToken, lpProcess, lpCommand, 0, 0, FALSE, CREATE_NEW_CONSOLE, 0, 0, &si, &pi);
//}
//
//int main()
//{
//	return CreateProceesByToken("spoolsv.exe", 0, "notepad.exe");
//}

int main()
{
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };

	StartupInfo.wShowWindow = SW_SHOW;
	StartupInfo.cb = sizeof(STARTUPINFO);
	StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

	if (!CreateProcessA(NULL,
		"C:\\Users\\leo00000\\Desktop\\test\\Debug\\test.exe",
		NULL,
		NULL,
		TRUE,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&StartupInfo,
		&ProcessInformation)) {
		printf("[-] Failed to Create Target Process: 0x%X\n", GetLastError());
		fflush(stdout);
		fflush(stderr);
		ExitProcess(-1);
	}

	//WaitForSingleObject(ProcessInformation.hProcess, INFINITE);

	// Close the open handles
	CloseHandle(ProcessInformation.hThread);
	CloseHandle(ProcessInformation.hProcess);

	return 0;
}