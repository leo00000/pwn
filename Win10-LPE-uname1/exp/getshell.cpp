#include "stdafx.h"
#include <winsock.h>

#define MYPORT 8756
#define BUFFER_SIZE 1024
#pragma comment(lib, "ws2_32.lib")

DWORD WINAPI ThreadInput(LPVOID lppram)
{
	SOCKET *client = (SOCKET *)lppram;
	char buf[BUFFER_SIZE];
	while (true)
	{
		gets_s(buf, BUFFER_SIZE);
		strcat_s(buf, "\r\n");
		send(*client, buf, strlen(buf), 0);

		if (!strncmp(buf, "exit\r\n", 6))
		{
			closesocket(*client);
			*client = INVALID_SOCKET;
			return FALSE;
		}
		Sleep(50);
	}

	return TRUE;
}

DWORD WINAPI ThreadOutput(LPVOID lppram)
{
	SOCKET *client = (SOCKET *)lppram;
	DWORD dwReceived = 0;
	char recvBuf[BUFFER_SIZE * 4 + 1] = { 0 };
	while (true)
	{
		if (*client == INVALID_SOCKET)
		{
			puts("bye!");
			fflush(stdout);
			return FALSE;
		}
		do
		{
			dwReceived = recv(*client, recvBuf, BUFFER_SIZE * 4, 0);
			printf(recvBuf);
			ZeroMemory(recvBuf, sizeof(recvBuf));
			fflush(stdout);
			fflush(stderr);
		} while (dwReceived > 0 && dwReceived != SOCKET_ERROR);
		
		Sleep(50);
	}

	return TRUE;
}

DWORD getshell()
{
	WSADATA wsaData = { 0 };
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	SOCKET client = INVALID_SOCKET;

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(MYPORT);
	serAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	connect(client, (sockaddr *)&serAddr, sizeof(serAddr));

	DWORD dwThreadInput = 0;
	DWORD dwThreadOutput = 0;
	HANDLE hThreadOutput = CreateThread(NULL, 0, ThreadOutput, &client, 0, &dwThreadOutput);
	HANDLE hThreadInput = CreateThread(NULL, 0, ThreadInput, &client, 0, &dwThreadInput);

	HANDLE szHandles[] = { hThreadOutput ,hThreadInput };
	WaitForMultipleObjects(2, szHandles, TRUE, INFINITE);

	if (client != INVALID_SOCKET)
	{
		closesocket(client);
	}
	WSACleanup();
	return 0;
}