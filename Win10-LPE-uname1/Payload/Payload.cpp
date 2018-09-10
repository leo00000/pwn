// Payload.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

int main()
{
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };

	StartupInfo.wShowWindow = SW_SHOW;
	StartupInfo.cb = sizeof(STARTUPINFO);
	StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

	if (!CreateProcessA(NULL,
		"C:\\Users\\leo00000\\Desktop\\exp\\x64\\Release\\shell.exe",
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