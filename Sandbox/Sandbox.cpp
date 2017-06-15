// Sandbox.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>



#define IPC_TEST_START_INDEX	3
#define IPC_TEST_ARG_LENGTH		2
#define	IPC_TEST_CREATE_FILE	0
#define IPC_TEST_CREATE_DIR		1




#define CREATEFILE				0
#define CREATEDIR 				1
#define INPUT	 				2
#define OUTPUT	 				3



typedef HANDLE(WINAPI * CreateFileFunc)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *CreateDirFunc)(_In_ LPCTSTR lpPathName, _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes);
typedef DWORD(WINAPI* InputFunc)(__in PWCHAR Input, __in DWORD InputSize);
typedef BOOL(WINAPI* OutputFunc)(__in PWCHAR Message);








#define MAX_PIPE_MESSAGE		2048
#define MESSAGE_MAX_LENGTH		1024
#define CREATE_FILE_REQUEST		1
#define ERROR_BUFFER			512
#define TEST1_INDEX				5
#define TESTS_LENGTHS			6


VOID HandleError(HANDLE out, const wchar_t* message, DWORD error) {
	wchar_t errorMessage[ERROR_BUFFER];
	ZeroMemory(errorMessage, ERROR_BUFFER * sizeof(wchar_t));
	swprintf_s(errorMessage, L"%s - %d\n", message, error);
	OutputDebugString(errorMessage);
	WriteFile(out, errorMessage, wcslen(errorMessage), NULL, NULL);
	ExitProcess(EXIT_FAILURE);
}


VOID Print(HANDLE out, LPCTSTR message) {
	WriteFile(out, message, wcslen(message) * sizeof(WCHAR), NULL, NULL);
}

BOOL CreateDirTest(HANDLE out, CreateDirFunc createDir, wchar_t* argv[]) {
	if (createDir(argv[IPC_TEST_START_INDEX + IPC_TEST_CREATE_DIR], NULL)) {
		Print(out, L"Create Dir Success.\n");
		return TRUE;
	}
	HandleError(out, L"Create Dir FAILED.\n", GetLastError());
	ExitProcess(EXIT_FAILURE);
	return FALSE;
}

BOOL CreateFileTest(HANDLE out, CreateFileFunc createFile, wchar_t* argv[]) {
	HANDLE file = createFile(argv[IPC_TEST_START_INDEX+ IPC_TEST_CREATE_FILE], 
		GENERIC_READ, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if (file != INVALID_HANDLE_VALUE) {
		DWORD readed = 0;
		WCHAR character= L'a';
		if (ReadFile(file, &character, sizeof(WCHAR), &readed, NULL) && readed == sizeof(WCHAR)) {
			Print(out, L"Create File Success.\n");
			return TRUE;
		}
	}
	HandleError(out, L"Create File FAILED.\n", GetLastError());
	ExitProcess(EXIT_FAILURE);
	return FALSE;
}

	
BOOL IPCTests(HANDLE out, FARPROC* SandBoxAPI, int argc, wchar_t* argv[]) {
	if (argc < IPC_TEST_ARG_LENGTH + IPC_TEST_START_INDEX || SandBoxAPI == NULL) {
		Print(out, L"Not enought arguments for IPC Tests");
		ExitProcess(EXIT_FAILURE);
	}
	/// Create File tests
	CreateFileFunc createFile = (CreateFileFunc)SandBoxAPI[CREATEFILE];
	CreateFileTest(out, createFile, argv);

	/// Create directory tests
	CreateDirFunc createDir = (CreateDirFunc)SandBoxAPI[CREATEDIR];
	CreateDirTest(out, createDir, argv);

	/// Create input tests
	InputFunc input = (InputFunc)SandBoxAPI[INPUT];
	WCHAR buffer[200];
	DWORD size = input(buffer, 200 * sizeof(WCHAR));
	if (size < 0 || size > 12 || !wcsncmp(buffer,L"Hi SB\n",size)) {
		Print(out, L"Input test failed.\n");
		ExitProcess(EXIT_FAILURE);
	}	

	OutputFunc outputf = (OutputFunc)SandBoxAPI[3];
	if (!outputf(buffer)) {
		Print(out, L"Output test failed.\n");
		ExitProcess(EXIT_FAILURE);
	}
	return TRUE;
}

BOOL TempFolderTest(HANDLE out, LPTSTR lpFolderPath)
{
	WCHAR buffer[512];
	ZeroMemory(buffer, 512);
	swprintf_s(buffer, L"%s\\tmp.txt", lpFolderPath);
	HANDLE file = CreateFile(buffer, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, NULL, NULL);
	if(file == INVALID_HANDLE_VALUE)
	{
		Print(out, L"Temp folder test failed - could not create.\n");
		ExitProcess(EXIT_FAILURE);
	}
	CloseHandle(file);
	if(!DeleteFile(buffer))
	{
		Print(out, L"Temp folder test failed - could not delete.\n");
		ExitProcess(EXIT_FAILURE);
	}
	Print(out, L"Temp folder test successed.\n");
	return TRUE;
}


BOOL InvalidCreateFileTest(HANDLE out, LPTSTR FileName)
{
	SetLastError(0);
	HANDLE test1 = CreateFile(FileName, GENERIC_READ, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	if (test1 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
		Print(out, L"Invalid create file test - SUCCESSED.\n");
	}
	else {
		Print(out, L"Invalid create file test - FAILED.\n");
		ExitProcess(EXIT_FAILURE);
	}
	return TRUE;
}


BOOL InvalidCreateWindowsTest(HANDLE out)
{
	SetLastError(0);
	if (!(!MessageBox(NULL, NULL, NULL, MB_OK) && GetLastError() == ERROR_ACCESS_DENIED))
	{
		Print(out, L"Invalied creating windows - FAILED.\n");
		ExitProcess(EXIT_FAILURE);
	}
	Print(out, L"Invalied creating windows - SUCCESSED.\n");
	return TRUE;
}


BOOL InvalidClipboardTests(HANDLE out)
{
	SetLastError(0);
	if (!GetClipboardData(CF_TEXT) && GetLastError() == ERROR_ACCESS_DENIED) {
		Print(out, L"Invalied Clipboard Test : Read - SUCCESSED.\n");
	}
	else {
		Print(out, L"Invalied Clipboard Test : Read - FAILED.\n");
		ExitProcess(EXIT_FAILURE);
	}

	SetLastError(0);
	if (!SetClipboardData(CF_TEXT, NULL) && GetLastError() == ERROR_ACCESS_DENIED) {
		Print(out, L"Invalied Clipboard Test : Write - SUCCESSED.\n");
	}
	else {
		Print(out, L"Invalied Clipboard Test : Write - FAILED.\n");
		ExitProcess(EXIT_FAILURE);
	}
	Print(out, L"Invalied Clipboard Test - SUCCESSED\n");
	return TRUE;
}

BOOL InvalidMouseTest(HANDLE out, OutputFunc outFunc, InputFunc inFunc)
{
	SetLastError(0);
	SetCursorPos(50, 50);
	outFunc(L"Test Mouse - did the mouse moved to (50,50)? Y/N");
	WCHAR buffer[20];
	if (inFunc(buffer, 20 * sizeof(WCHAR)) && buffer[0] == L'Y') {
		Print(out, L"Invalid Mouse Test - SUCCESSED.\n");
	}
	else
	{
		Print(out, L"Invalid Mouse Test - FAILED.\n");
	}
	return TRUE;
}

BOOL InvalidCD(HANDLE out)
{
	if (!(!SetCurrentDirectory(L"C:\\") && GetLastError() == ERROR_ACCESS_DENIED)) {
		Print(out, L"Invalid CD - FAILED.\n");
		ExitProcess(EXIT_FAILURE);
	}
	Print(out, L"Invalid CD - SUCCESSED.\n");
	return TRUE;
}

BOOL SBTEST(HANDLE out, OutputFunc outFunc, InputFunc inFunc)
{
	InvalidCreateFileTest(out, L"C:\\a.txt");
	InvalidCreateWindowsTest(out);
	InvalidCD(out);
	InvalidClipboardTests(out);
	InvalidMouseTest(out, outFunc, inFunc);
	return TRUE;
}


int _tmain(int argc, wchar_t* argv[])
{
	if (argc < 3) {
		ExitProcess(EXIT_FAILURE);
	}
	HANDLE out;
	swscanf_s(argv[2], L"%p", &out);

	///***************************************************************///
	///						Start IPC Tests
	///***************************************************************///
	HMODULE sandboxAPI = GetModuleHandle(L"SandboxDLL.dll");
	if (sandboxAPI == 0) {
		Print(out, L"Could not get sanbox api.\n");
		ExitProcess(EXIT_FAILURE);
	}

	FARPROC SandBoxAPI[4];
	SandBoxAPI[CREATEFILE] = GetProcAddress(sandboxAPI, "SBCreateFile");
	SandBoxAPI[CREATEDIR]  = GetProcAddress(sandboxAPI, "SBCreateDirectory");
	SandBoxAPI[INPUT]      = GetProcAddress(sandboxAPI, "SBHandleInput");
	SandBoxAPI[OUTPUT]     = GetProcAddress(sandboxAPI, "SBHandleOutput");

	IPCTests(out, SandBoxAPI, argc, argv);
	TempFolderTest(out, argv[1]);
	SBTEST(out,(OutputFunc)SandBoxAPI[OUTPUT], (InputFunc)SandBoxAPI[INPUT]);
	((OutputFunc)SandBoxAPI[OUTPUT])(L"ALL FINISHED!");
}