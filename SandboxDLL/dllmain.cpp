// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <shellapi.h>
#include <stdlib.h>
#include "RequestHandler.h"
#include "Hooker.h"

#define ERROR_BUFFER			512
#define pointerFromRVA(base, rvd) (((char*)base)+((int)rvd))

typedef struct {
	HANDLE read;
	HANDLE write;
} DataToChild;


RequestHandler* requestHandler					= NULL;
CreateFileW_Orign createFileW					= NULL;
CreateDirectory_Origin createDirectoryW			= NULL;

///<summery>
/// hooked function for CreateFileW (CreateFileA call this), 
/// the hook use IPC to send the request to the broker.
///</summery>
HANDLE WINAPI HookedCreateFileW(
	_In_     LPCTSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile
)
{
	if (requestHandler == NULL) {
		SetLastError(ERROR_ACCESS_DENIED);
		return INVALID_HANDLE_VALUE;
	}
	return requestHandler->CreateFileViaBroker(
		lpFileName, dwDesiredAccess, dwShareMode, 
		lpSecurityAttributes, dwCreationDisposition, 
		dwFlagsAndAttributes, hTemplateFile);
}


///<summery>
/// hooked function for CreateFileW (CreateFileA call this), 
/// the hook use IPC to send the request to the broker.
///</summery>
BOOL HookedCreateDirectoryW(
	_In_     LPCTSTR               lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
	if (requestHandler == NULL) {
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}
	return requestHandler->CreateDirectoryViaBroker(lpPathName, lpSecurityAttributes);
}






///<summery>Get the entry point of the given module</summery>
///<param name='module'>the module</param>
///<return>the entry point</return>
DWORD GetEntryPoint(__in HMODULE module) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)pointerFromRVA(module, dosHeader->e_lfanew);
	return (DWORD)pointerFromRVA(module, (ntHeader->OptionalHeader).AddressOfEntryPoint);
}

///<summery>print an error to the output debug stream while formating the message</summary>
///<param name='Message'>The error message</param>
///<param name='Error'>The GetLastError code</param>
VOID HandleError(__in const PWCHAR Message, __in DWORD Error) {
	wchar_t errorMessage[ERROR_BUFFER];
	ZeroMemory(errorMessage, ERROR_BUFFER * sizeof(wchar_t));
	swprintf_s(errorMessage, L"%s - %d\n", Message, Error);
	OutputDebugString(errorMessage);
	wprintf(L"%s %d\n", Message, Error);
}


///<summery>extract argc & argv from the program commandline</summary>
///<param name='argc'>the number of argument in the process</param>
///<return>List of wide character string that include the arguments</return>
LPWSTR* ParseProgramParameter(__out PINT argc) {
	LPWSTR* argv = CommandLineToArgvW(GetCommandLine(), argc);
	if (argv == NULL && *argc > 0) {
		TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
	}
	return argv;
}


DWORD SetParameters(_In_ LPVOID lpParameter) {
	DataToChild* data = (DataToChild*)lpParameter;
	if (requestHandler == NULL) {
		requestHandler = new RequestHandler(NULL, data->read, data->write);
		return TRUE;
	}
	else {
		HandleError(L"Failed to create IPC! ", GetLastError());
		TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
	}
	return FALSE;
}

VOID SandBoxMain() {
	DWORD entry = GetEntryPoint(GetModuleHandle(NULL));

	/// parse program parameter
	int argc;
	LPWSTR* argv = ParseProgramParameter(&argc);

	/// Now we decrease permission & privilleges
	if (!RevertToSelf()) {
		HandleError(L"Failed to revert back to low privilenges.", GetLastError());
		TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
	}

	/// Create IPC object
	if (requestHandler != NULL){// == NULL) {
		
		/// Hook functions to make it easier for the process
		if (!requestHandler->NotifyOnInitilizationComplete()) {
			HandleError(L"Failed to notify on finish initilization.", GetLastError());
			TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
		}
		patchIAT(GetModuleHandle(NULL), "Kernel32.dll", "CreateFileW", &HookedCreateFileW, (PVOID*)&createFileW);
		patchIAT(GetModuleHandle(NULL), "Kernel32.dll", "CreateDirectoryW", &HookedCreateDirectoryW, (PVOID*)&createDirectoryW);
		
		/// Go to entry
		((void(*)(void))entry)();
	}
	else {
		HandleError(L"Failed to create IPC.", GetLastError());
		TerminateProcess(GetCurrentProcess(), EXIT_FAILURE);
	}
}









BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{		
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

