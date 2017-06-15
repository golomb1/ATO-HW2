// Broker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <Sddl.h>
#include <aclapi.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include "RestrictedProcess.h"
#include <malloc.h>
#include "PipeIPC.h"
#include "RequestHandler.h"
#include "Policy.h"

typedef struct {
	PROCESS_INFORMATION ChildProcInfo;
	Policy*				pPolicy;
} IPCData;

#define			NUM_OF_INHERITED_HANDLES	2
#define			MAX_DESKTOP_NAME_SIZE		256

///************************************************************///
///						Broker API operations
///************************************************************///

///<summery>
///Handle Finish Initilization request by lowering the process mandatory level
///Ignore the rest of the parameters.
///</summery>
PVOID BrokerLowerPrivilege(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	IPCData* ipcData = (IPCData*)Data;
	PBOOL result = (PBOOL)GlobalAlloc(GPTR, sizeof(BOOL));
	*result = SetProcessUntrusted(ipcData->ChildProcInfo.hProcess) == NO_ERROR;
	*size = sizeof(BOOL);
	printf("Child process finished with it's initilization, status is %s\n", *result ? "Untrusted" : "non-Untrusted");
	return result;
}


PVOID BrokerCreateFile(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	IPCData* ipcData = (IPCData*)Data;
	PHANDLE file1 = (PHANDLE)GlobalAlloc(GPTR, sizeof(HANDLE));
	(*file1) = INVALID_HANDLE_VALUE;
	if (lentgh >= sizeof(CreateFileRequest)) {

		/// Read parameters
		CreateFileRequest* requestHeader = (CreateFileRequest*)request;
		if (lentgh >= sizeof(CreateFileRequest) + requestHeader->NameLength + requestHeader->lpSecurityAttributesLength) {
			wchar_t* name = new wchar_t[requestHeader->NameLength];
			ZeroMemory(name, sizeof(name));
			wcscpy_s(name, requestHeader->NameLength, (wchar_t*)(request + sizeof(CreateFileRequest)));

			/// Create the relevant security attribute.
			PBYTE sa = NULL;
			if (requestHeader->lpSecurityAttributesLength > 0) {
				sa = new byte[requestHeader->lpSecurityAttributesLength];
				memcpy_s(&sa,
					requestHeader->lpSecurityAttributesLength,
					request + sizeof(CreateFileRequest) + requestHeader->NameLength,
					requestHeader->lpSecurityAttributesLength);
			}

			if (!((ipcData->pPolicy)->HaveAccessToFile(
				name, requestHeader->dwDesiredAccess,
				requestHeader->dwShareMode, requestHeader->dwFlagsAndAttributes)))
			{
				SetLastError(ERROR_ACCESS_DENIED);
				(*file1) = INVALID_HANDLE_VALUE;
			}
			else {
				/// Create the file
				HANDLE file = CreateFile(name,
					requestHeader->dwDesiredAccess,
					requestHeader->dwShareMode,
					(LPSECURITY_ATTRIBUTES)sa,
					requestHeader->dwCreationDisposition,
					requestHeader->dwFlagsAndAttributes,
					requestHeader->hTemplateFile);

				/// Allocate the duplicate handle for the child and return it.
				HANDLE duplicateHandle;
				HANDLE prs = OpenProcess(PROCESS_DUP_HANDLE, FALSE, GetCurrentProcessId());
				HANDLE prd = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ipcData->ChildProcInfo.dwProcessId);
				if (!DuplicateHandle(prs, file, prd, &duplicateHandle, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
					OutputDebugString(L"Could not duplicate the handle to sandbox.");
					(*file1) = INVALID_HANDLE_VALUE;
				}
				else {
					(*file1) = duplicateHandle;
				}
			}
		}
		else {
			SetLastError(ERROR_INVALID_PARAMETER);
		}
	}
	else {
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	(*size) = sizeof(HANDLE);
	return file1;
}


PVOID BrokerCreateDirectory(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	IPCData* ipcData = (IPCData*)Data;
	BOOL result = FALSE;
	if (lentgh >= sizeof(CreateDirectoryRequest)) {
		/// Read parameters
		CreateDirectoryRequest* requestHeader = (CreateDirectoryRequest*)request;
		if (lentgh >= sizeof(CreateDirectoryRequest) + requestHeader->NameLength + requestHeader->lpSecurityAttributesLength) {
			PWCHAR name = new WCHAR[requestHeader->NameLength];
			ZeroMemory(name, sizeof(name));
			wcscpy_s(name, requestHeader->NameLength, (PWCHAR)(request + sizeof(CreateDirectoryRequest)));

			/// Create the relevant security attribute.
			PBYTE sa = NULL;
			if (requestHeader->lpSecurityAttributesLength > 0) {
				sa = new byte[requestHeader->lpSecurityAttributesLength];
				memcpy_s(&sa,
					requestHeader->lpSecurityAttributesLength,
					request + sizeof(CreateDirectoryRequest) + requestHeader->NameLength,
					requestHeader->lpSecurityAttributesLength);
			}

			/// Create the file

			if ((ipcData->pPolicy)->HaveAccessToDirectory(name)) {
				result = CreateDirectory(name, (LPSECURITY_ATTRIBUTES)sa);
			}
			else {
				SetLastError(ERROR_ACCESS_DENIED);
			}
		}
		else {
			SetLastError(ERROR_INVALID_PARAMETER);
		}
	}
	else {
		SetLastError(ERROR_INVALID_PARAMETER);
	}
	/// Allocate the duplicate handle for the child and return it.
	PBOOL retResult = (PBOOL)GlobalAlloc(GPTR, sizeof(BOOL));
	(*retResult) = result;
	(*size) = sizeof(HANDLE);
	return retResult;
}


PVOID BrokerHandleInput(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	using namespace std;
	IPCData* ipcData = (IPCData*)Data;
	if (lentgh >= sizeof(DWORD)) {
		DWORD inputSize = *((PDWORD)request);
		PWCHAR result = (PWCHAR)GlobalAlloc(GPTR, inputSize);
		printf("Sandbox ask for input: ");
		std::wcin.get(result, inputSize);
		*size = inputSize;
		return result;
	}
	*size = 0;
	return NULL;
}



PVOID BrokerHandleOutput(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	IPCData* ipcData = (IPCData*)Data;
	wprintf(L"Sandbox Said: %s\n", (PWCHAR)request);
	PBOOL result = (PBOOL)GlobalAlloc(GPTR, sizeof(BOOL));
	*result = TRUE;
	*size = sizeof(BOOL);
	return result;
}


///************************************************************///
///						Main
///************************************************************///

int _tmain(int argc, wchar_t* argv[])
{
	/// Initilize pipes for IPC
	HANDLE ParentReadHandle, ChildWriteHandle;
	HANDLE ChildReadHandle, ParentWriteHandle;

	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof(sa);

	if (!CreatePipe(&ParentReadHandle, &ChildWriteHandle , &sa, MAX_PIPE_MESSAGE) || 
		!CreatePipe(&ChildReadHandle , &ParentWriteHandle, &sa, MAX_PIPE_MESSAGE)) {
		printf("Could not create pipes for IPC, error was: %d.\nExiting...", GetLastError());
		ExitProcess(EXIT_FAILURE);
	}


	IPCData DataForIPC;
	ZeroMemory(&DataForIPC, sizeof(IPCData));
	RequestHandler ipc(&DataForIPC, ParentReadHandle, ParentWriteHandle);
	ipc.SetHandler(NOTIFY_PROCESS_INITLIZATION_COMPLETE	, BrokerLowerPrivilege);
	ipc.SetHandler(CREATE_FILE_REQUEST_TYPE				, BrokerCreateFile);
	ipc.SetHandler(CREATE_DIRECTORY_REQUEST_TYPE		, BrokerCreateDirectory);
	ipc.SetHandler(HANDLE_INPUT_REQUEST					, BrokerHandleInput);
	ipc.SetHandler(HANDLE_OUTPUT_REQUEST				, BrokerHandleOutput);



	/// Create untrusted directory
	if (!CreateUntrustedFolder(argv[2])) {
		printf("Could not create folder for sandbox, error was: %d.\nExiting...", GetLastError());
		ExitProcess(EXIT_FAILURE);
	}

	/// Read Policy file
	DataForIPC.pPolicy = new Policy();
	DataForIPC.pPolicy->ParsePolicyFile(argv[3]);

	HANDLE InitilizationToken	= NULL;
	HANDLE PrimaryToken			= NULL;
	HANDLE impersonation_token  = NULL;

	WCHAR  AppPath[1024];
	PWCHAR CmdLine;
	WCHAR  CmdLineBuf[1024];
	
	/// Create the process command line
	if (_snwprintf_s(CmdLineBuf, 1023, L"\"%s\" %s", argv[1], argv[2]) < 0)
	{
		printf("Command line argument too long, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(argv[2]);
		delete DataForIPC.pPolicy;
		ExitProcess(EXIT_FAILURE);
	}
	CmdLineBuf[1023] = '\0';
	CmdLine = CmdLineBuf;
	wcscpy_s(AppPath, argv[1]);

	PrimaryToken = RestrictProcessToken(TRUE);
	InitilizationToken = RestrictProcessToken(FALSE);
	HANDLE inheritanceHandles[NUM_OF_INHERITED_HANDLES];
	inheritanceHandles[0] = ChildReadHandle;
	inheritanceHandles[1] = ChildWriteHandle;
	
	if (PrimaryToken == INVALID_HANDLE_VALUE) {
		printf("Could not create primary token, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(argv[2]);
		delete DataForIPC.pPolicy;
		ExitProcess(EXIT_FAILURE);
	}
	if (InitilizationToken == INVALID_HANDLE_VALUE || 
		!DuplicateToken(InitilizationToken, SecurityImpersonation, &impersonation_token)) {
		printf("Could not create Initilization token, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(argv[2]);
		ExitProcess(EXIT_FAILURE);
	}

	/// Generate parameter names:
	WCHAR DesktopName[MAX_DESKTOP_NAME_SIZE];
	ZeroMemory(DesktopName, MAX_DESKTOP_NAME_SIZE);
	swprintf_s(DesktopName, L"%s-%d", L"SandBox", GetTickCount());

	DataToChild data;
	ZeroMemory(&data, sizeof(DataToChild));
	data.read  = ChildReadHandle;
	data.write = ChildWriteHandle;

	/// Generate dll hook functions
	DLLFunction Entry;
	ZeroMemory(&Entry, sizeof(DLLFunction));
	Entry.FunctionNameInDll = "SandBoxMain";
	Entry.FunctionOrdinalInDll = 1;
	Entry.FunctionIsOrdinal = TRUE;

	DLLFunction SetParam;
	ZeroMemory(&SetParam, sizeof(DLLFunction));
	SetParam.FunctionNameInDll = "SetParameters";
	SetParam.FunctionOrdinalInDll = 2;
	SetParam.FunctionIsOrdinal = TRUE;


	if(!CreateRestrictedProcess(
			PrimaryToken, impersonation_token, DesktopName, NUM_OF_INHERITED_HANDLES, 
			inheritanceHandles, AppPath, CmdLine, argv[2], L"C:\\SandboxDLL.dll", sizeof(WCHAR)*wcslen(L"C:\\SandboxDLL.dll"),
		Entry, SetParam, data, &(DataForIPC.ChildProcInfo)))
	{
		printf("Created restricted process failed %d\n", GetLastError()); 
		RemoveDirectory(argv[2]);
		delete DataForIPC.pPolicy;
		ExitProcess(EXIT_FAILURE);
	}

	DWORD processExitCode = 0;
	GetExitCodeProcess(DataForIPC.ChildProcInfo.hProcess, &processExitCode);
	while (processExitCode == STILL_ACTIVE) {
		ipc.HandleMessage();
		GetExitCodeProcess(DataForIPC.ChildProcInfo.hProcess, &processExitCode);
	}
	RemoveDirectory(argv[2]);
	delete DataForIPC.pPolicy;
	ExitProcess(EXIT_SUCCESS);
}
