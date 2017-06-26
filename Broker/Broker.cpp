// Broker.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <Sddl.h>
#include <aclapi.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include "RestrictedProcess.h"
#include "PipeIPC.h"
#include "RequestHandler.h"
#include "Policy.h"
#include "cmdline.h"


typedef struct {
	PROCESS_INFORMATION ChildProcInfo;
	Policy*				pPolicy;
} IPCData;

#define			MAX_DESKTOP_NAME_SIZE		256
#define			TEMP_DIRECTORY_PATH_LENGTH	1024

#define			TEMP_FOLDER_ARG_ID			1
#define			INPUT_ARG_ID				2
#define			OUTPUT_ARG_ID				3
#define			POLICY_ARG_ID				4
#define			TO_RUN_ARG_ID				5

#define			DLL_PATH					L".\\SandboxDLL.dll"


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
	*file1 = INVALID_HANDLE_VALUE;
	if (lentgh >= sizeof(CreateFileRequest)) {

		/// Read parameters
		CreateFileRequest* requestHeader = (CreateFileRequest*)request;
		if (lentgh >= sizeof(CreateFileRequest) + requestHeader->NameLength + requestHeader->lpSecurityAttributesLength) {
			wchar_t* name = new wchar_t[requestHeader->NameLength];
			ZeroMemory(name, sizeof name);
			wcscpy_s(name, requestHeader->NameLength, (wchar_t*)(request + sizeof(CreateFileRequest)));

			/// Create the relevant security attribute.
			PBYTE sa = nullptr;
			if (requestHeader->lpSecurityAttributesLength > 0) {
				sa = new byte[requestHeader->lpSecurityAttributesLength];
				memcpy_s(&sa,
					requestHeader->lpSecurityAttributesLength,
					request + sizeof(CreateFileRequest) + requestHeader->NameLength,
					requestHeader->lpSecurityAttributesLength);
			}

			if (!ipcData->pPolicy->HaveAccessToFile(
				name, requestHeader->dwDesiredAccess,
				requestHeader->dwShareMode, requestHeader->dwFlagsAndAttributes))
			{
				SetLastError(ERROR_ACCESS_DENIED);
				*file1 = INVALID_HANDLE_VALUE;
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
					*file1 = INVALID_HANDLE_VALUE;
				}
				else {
					*file1 = duplicateHandle;
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
	*size = sizeof(HANDLE);
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
			ZeroMemory(name, sizeof name);
			wcscpy_s(name, requestHeader->NameLength, (PWCHAR)(request + sizeof(CreateDirectoryRequest)));

			/// Create the relevant security attribute.
			PBYTE sa = nullptr;
			if (requestHeader->lpSecurityAttributesLength > 0) {
				sa = new byte[requestHeader->lpSecurityAttributesLength];
				memcpy_s(&sa,
					requestHeader->lpSecurityAttributesLength,
					request + sizeof(CreateDirectoryRequest) + requestHeader->NameLength,
					requestHeader->lpSecurityAttributesLength);
			}

			/// Create the file

			if (ipcData->pPolicy->HaveAccessToDirectory(name)) {
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
	*retResult = result;
	*size = sizeof(HANDLE);
	return retResult;
}


PVOID BrokerHandleInput(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	using namespace std;
	if (lentgh >= sizeof(DWORD)) {
		DWORD inputSize = *(PDWORD)request;
		PWCHAR result = (PWCHAR)GlobalAlloc(GPTR, inputSize);
		ZeroMemory(result, inputSize);
		printf("Sandbox ask for input: ");
		*size = 2;
		while (*size == 2) {
			wcin.get(result, inputSize);
			cin.ignore();
			*size = (wcslen(result) + 1) * sizeof(WCHAR);
		}
		return result;
	}
	*size = 0;
	return nullptr;
}



PVOID BrokerHandleOutput(__in PVOID Data, __in PBYTE request, __in DWORD lentgh, __out PDWORD size) {
	wprintf(L"Sandbox Said: %s\n", (PWCHAR)request);
	PBOOL result = (PBOOL)GlobalAlloc(GPTR, sizeof(BOOL));
	*result = TRUE;
	*size = sizeof(BOOL);
	return result;
}


///************************************************************///
///						Broker
///************************************************************///

DWORD WINAPI HandleSandboxMessages(_In_ LPVOID lpParameter)
{
	DWORD processExitCode = 0;
	LPVOID* lpP = (LPVOID*)lpParameter;
	IPCData* DataForIPC = (IPCData*)lpP[0];
	RequestHandler* ipc = (RequestHandler*)lpP[1];
	GetExitCodeProcess(DataForIPC->ChildProcInfo.hProcess, &processExitCode);
	while (processExitCode == STILL_ACTIVE) {
		ipc->HandleMessage();
		GetExitCodeProcess(DataForIPC->ChildProcInfo.hProcess, &processExitCode);
	}
	return EXIT_SUCCESS;
}


DWORD StartBroker(LPWSTR tempDir, LPWSTR policyPath, LPWSTR targetPath, LPWSTR targetArgs, HANDLE in, HANDLE out) {
	/// Initilize pipes for IPC
	HANDLE ParentReadHandle, ChildWriteHandle;
	HANDLE ChildReadHandle, ParentWriteHandle;

	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.bInheritHandle = TRUE;
	sa.nLength = sizeof sa;

	if (!CreatePipe(&ParentReadHandle, &ChildWriteHandle, &sa, MAX_PIPE_MESSAGE) ||
		!CreatePipe(&ChildReadHandle, &ParentWriteHandle, &sa, MAX_PIPE_MESSAGE)) {
		printf("Could not create pipes for IPC, error was: %d.\nExiting...", GetLastError());
		return EXIT_FAILURE;
	}


	IPCData DataForIPC;
	ZeroMemory(&DataForIPC, sizeof(IPCData));
	RequestHandler ipc(&DataForIPC, ParentReadHandle, ParentWriteHandle);
	ipc.SetHandler(NOTIFY_PROCESS_INITLIZATION_COMPLETE, BrokerLowerPrivilege);
	ipc.SetHandler(CREATE_FILE_REQUEST_TYPE, BrokerCreateFile);
	ipc.SetHandler(CREATE_DIRECTORY_REQUEST_TYPE, BrokerCreateDirectory);
	ipc.SetHandler(HANDLE_INPUT_REQUEST, BrokerHandleInput);
	ipc.SetHandler(HANDLE_OUTPUT_REQUEST, BrokerHandleOutput);


	/// Create untrusted directory
	WCHAR TempDirectory[TEMP_DIRECTORY_PATH_LENGTH];
	ZeroMemory(TempDirectory, TEMP_DIRECTORY_PATH_LENGTH * sizeof(WCHAR));

	DWORD TempDirectoryLength;
	if (tempDir != nullptr) {
		TempDirectoryLength = GetFullPathName(tempDir,
			TEMP_DIRECTORY_PATH_LENGTH, TempDirectory, nullptr);
	}
	else
	{
		printf("Could not Find the path for the given sandbox directory, got null.\nExiting...");
		return EXIT_FAILURE;
	}
	if (TempDirectoryLength == 0)
	{
		printf("Could not Find the full path for the given sandbox directory, error was: %d.\nExiting...", GetLastError());
		return EXIT_FAILURE;
	}
	CreateUntrustedFolder(TempDirectory);

	/// Read Policy file
	DataForIPC.pPolicy = new Policy();
	DataForIPC.pPolicy->ParsePolicyFile(policyPath);

	HANDLE impersonation_token = nullptr;

	WCHAR  AppPath[1024];
	WCHAR  CmdLineBuf[1024];

	SECURITY_ATTRIBUTES outSa;
	ZeroMemory(&outSa, sizeof(SECURITY_ATTRIBUTES));
	outSa.bInheritHandle = TRUE;
	outSa.nLength = sizeof outSa;
	/// Create the process command line
	if (_snwprintf_s(CmdLineBuf, 1023, L"\"%s\" \"%s\" %s", targetPath, TempDirectory, targetArgs) < 0)
	{
		printf("Command line argument too long, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(TempDirectory);
		delete DataForIPC.pPolicy;
		return EXIT_FAILURE;
	}
	CmdLineBuf[1023] = '\0';
	PWCHAR CmdLine = CmdLineBuf;
	wcscpy_s(AppPath, targetPath);

	HANDLE PrimaryToken = RestrictProcessToken(TRUE);
	HANDLE InitilizationToken = RestrictProcessToken(FALSE);

	DWORD numOfInheritanceHandles = 2;
	if (in != INVALID_HANDLE_VALUE) {
		numOfInheritanceHandles++;
	}
	if (out != INVALID_HANDLE_VALUE) {
		numOfInheritanceHandles++;
	}
	HANDLE* inheritanceHandles = new HANDLE[numOfInheritanceHandles];
	inheritanceHandles[0] = ChildReadHandle;
	inheritanceHandles[1] = ChildWriteHandle;
	DWORD index = 2;
	if (in != INVALID_HANDLE_VALUE) {
		inheritanceHandles[index] = in;
		index++;
	}
	if (out != INVALID_HANDLE_VALUE) {
		inheritanceHandles[index] = out;
	}

	if (PrimaryToken == INVALID_HANDLE_VALUE) {
		printf("Could not create primary token, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(TempDirectory);
		delete DataForIPC.pPolicy;
		return EXIT_FAILURE;
	}
	if (InitilizationToken == INVALID_HANDLE_VALUE ||
		!DuplicateToken(InitilizationToken, SecurityImpersonation, &impersonation_token)) {
		printf("Could not create Initilization token, Error was: %d\nExiting...", GetLastError());
		RemoveDirectory(TempDirectory);
		return EXIT_FAILURE;
	}

	/// Generate parameter names:
	WCHAR DesktopName[MAX_DESKTOP_NAME_SIZE];
	ZeroMemory(DesktopName, MAX_DESKTOP_NAME_SIZE);
	swprintf_s(DesktopName, L"%s-%d", L"SandBox", GetTickCount());

	DataToChild data;
	ZeroMemory(&data, sizeof(DataToChild));
	data.read = ChildReadHandle;
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

	WCHAR dllPath[TEMP_DIRECTORY_PATH_LENGTH];
	ZeroMemory(dllPath, sizeof(WCHAR)* TEMP_DIRECTORY_PATH_LENGTH);
	swprintf_s(dllPath, L"%s\\SandboxDLL.dll", TempDirectory);


	if (!CopyFile(DLL_PATH, dllPath, FALSE))
	{
		printf("Could not set dll at c directory - error %d\n", GetLastError());
		RemoveDirectory(TempDirectory);
		delete DataForIPC.pPolicy;
		return EXIT_FAILURE;
	}

	if (!CreateRestrictedProcess(
		PrimaryToken, impersonation_token, DesktopName, numOfInheritanceHandles,
		inheritanceHandles, in ,out, AppPath, CmdLine, TempDirectory, dllPath, sizeof(WCHAR)*wcslen(dllPath),
		Entry, SetParam, data, &DataForIPC.ChildProcInfo))
	{
		printf("Created restricted process failed %d\n", GetLastError());
		RemoveDirectory(TempDirectory);
		delete DataForIPC.pPolicy;
		return EXIT_FAILURE;
	}

	LPVOID param[2];
	param[0] = &DataForIPC;
	param[1] = &ipc;
	CreateThread(nullptr, 0, HandleSandboxMessages, param, 0, nullptr);
	
	WaitForSingleObject(DataForIPC.ChildProcInfo.hProcess, INFINITE);
	
	RemoveDirectory(TempDirectory);
	delete DataForIPC.pPolicy;
	return EXIT_SUCCESS;
}




///************************************************************///
///						Main
///************************************************************///

int _tmain(int argc, wchar_t* argv[])
{
	cmdline parser(argv[0], L"Sandbox application");
	BOOL parserInit = parser.AddOption(POLICY_ARG_ID, wstring(L"-p"), wstring(L"-Policy"), wstring(L"policy_file_path"), wstring(L"- Target policy"), TRUE, FALSE, FALSE);
	parserInit |= parser.AddOption(TEMP_FOLDER_ARG_ID, wstring(L"-t"), wstring(L"-TEMP-DIR"), wstring(L"temp_dir_path"), wstring(L"- Process Temp folder"), TRUE, FALSE, FALSE);
	//parserInit |= parser.AddOption(INPUT_ARG_ID, wstring(L"-i"), wstring(L"-Input"), wstring(L"- Sandbox input support"), FALSE, TRUE, FALSE);
	//parserInit |= parser.AddOption(OUTPUT_ARG_ID, wstring(L"-o"), wstring(L"-Output"), wstring(L"- Sandbox output support"), FALSE, TRUE, FALSE);
	parserInit |= parser.AddOption(TO_RUN_ARG_ID, wstring(L"-toRun"), wstring(L"-toRrun"), wstring(L"target_path"), wstring(L"- Sandbox target program"), TRUE, FALSE, TRUE);
	if (!parserInit)
	{
		printf("Could not parse command line.\nExiting...");
		ExitProcess(EXIT_FAILURE);
	}
	parser.parse(argc, argv);


	LPWSTR policyPath = parser.GetArg(POLICY_ARG_ID);
	LPWSTR tempPath = parser.GetArg(TEMP_FOLDER_ARG_ID);
	//BOOL inputFlag = parser.GetArg(INPUT_ARG_ID) != nullptr;
	//BOOL outputFlag = parser.GetArg(INPUT_ARG_ID) != nullptr;
	LPWSTR toRun = parser.GetArg(TO_RUN_ARG_ID);
	DWORD paramIndex = parser.GetArgIndex(TO_RUN_ARG_ID);
	if(paramIndex == ~0 || paramIndex + 1 > (DWORD)argc)
	{
		printf("Could not collect target command line.\nExiting...");
		ExitProcess(EXIT_FAILURE);
	}
	HANDLE in  = INVALID_HANDLE_VALUE;
	HANDLE out = INVALID_HANDLE_VALUE;

	/*if (inputFlag || outputFlag)
	{
		SECURITY_ATTRIBUTES sa;
		ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
		sa.bInheritHandle = TRUE;
		sa.nLength = sizeof sa;
		if (!CreatePipe(&in, &out, &sa, MAX_PIPE_MESSAGE)) {
			printf("Could not create pipes for redirection, error was: %d.\nExiting...", GetLastError());
			ExitProcess(EXIT_FAILURE);
		}
		if (!inputFlag)
		{
			CloseHandle(in);
			in = INVALID_HANDLE_VALUE;
		}
		if (!outputFlag)
		{
			CloseHandle(out);
			out = INVALID_HANDLE_VALUE;
		}
	}*/
	
	
	wstring target_params(L"");
	for(int i= paramIndex + 2; i < argc; i++)
	{
		target_params.append(argv[i]);
		target_params.append(L" ");
	}
	WCHAR params[1024];
	ZeroMemory(params , sizeof(WCHAR)*1024);
	swprintf_s(params, L"%s", target_params.c_str());
	// create a thread to wait for user command
	DWORD exit_code = StartBroker(tempPath, policyPath, toRun, params, in, out);
	system("pause");
	ExitProcess(exit_code);
}
