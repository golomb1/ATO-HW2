// Sandbox.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

#define MAX_PIPE_MESSAGE		2048
#define MESSAGE_MAX_LENGTH		1024
#define CREATE_FILE_REQUEST		1
#define ERROR_BUFFER			512
#define TEST1_INDEX				5
#define TESTS_LENGTHS			6
void HandleError(const wchar_t* message, DWORD error) {
	wchar_t errorMessage[ERROR_BUFFER];
	ZeroMemory(errorMessage, ERROR_BUFFER * sizeof(wchar_t));
	swprintf_s(errorMessage, L"%s - %d\n", message, error);
	OutputDebugString(errorMessage);
	wprintf(L"%s %d\n", message, error);
}



ULONG SetProcessUntrusted(HANDLE hProcess)
{
	TOKEN_MANDATORY_LABEL tml = { { (PSID)alloca(MAX_SID_SIZE), SE_GROUP_INTEGRITY } };

	ULONG cb = MAX_SID_SIZE;

	HANDLE hToken;

	if (!CreateWellKnownSid(WinLowLabelSid, 0, tml.Label.Sid, &cb) ||
		!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken))
	{
		return GetLastError();
	}

	ULONG dwError = NOERROR;
	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof(tml)))
	{
		dwError = GetLastError();
	}

	CloseHandle(hToken);

	return dwError;
}

int _tmain(int argc, wchar_t* argv[])
{
	HANDLE writePipe;
	HANDLE readPipe;
	OutputDebugString(L"((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((\n\n\n\n\n\n\n\n\n.");
	printf("((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((\n\n\n\n\n\n");
	printf("WINSTATION is %p and windows is %p\n\n", GetProcessWindowStation(), GetThreadDesktop(GetCurrentThreadId()));
	
	ULONG e = SetProcessUntrusted(GetCurrentProcess());
	if (e == NO_ERROR) {
		printf("dgkjvdkfjkb Faile:feigrljhlidrjhljrhlFAILLLLLLLLLLLLLLLLLLLL\n");
	}
	else {
		printf(":) good for me%d\n",e);
	}

	
	if (argc < 3) {
		OutputDebugString(L"Not enough arguments.");
		return EXIT_FAILURE;
	}
	/// Read the read handle
	swscanf_s(argv[2], L"%p", &readPipe);
	if (readPipe == INVALID_HANDLE_VALUE) {
		HandleError(L"Failed to create read Pipe! ", GetLastError());
		return EXIT_FAILURE;
	}
	/// Read the write handle
	swscanf_s(argv[1], L"%p", &writePipe);
	if (writePipe == INVALID_HANDLE_VALUE) {
		HandleError(L"Failed to create write Pipe! ",GetLastError());
		return EXIT_FAILURE;
	}

	/// Now we decrease permission & privilleges
	if (!RevertToSelf()) {
		HandleError(L"Failed to revert back to low privilenges.", GetLastError());
		return EXIT_FAILURE;
	}

	/// restrict to untrusted.
	if (argc > TESTS_LENGTHS) {
		HANDLE test;
		DWORD a;
		swscanf_s(argv[3], L"%p", &test);
		WriteFile(test, L"Hgtsfdt\n", 8 * sizeof(wchar_t), &a, NULL);
		{
			wchar_t b[4098];
			wchar_t ou[4098];
			DWORD a;
			GetUserObjectInformation(GetProcessWindowStation(), UOI_NAME, b, 4098 * 2, &a);
			swprintf_s(ou, L"|||||||||| %s \n", b);
			WriteFile(test, ou, wcslen(ou) * sizeof(wchar_t), &a, NULL);
			WriteFile(test, L"\n", 1 * sizeof(wchar_t), &a, NULL);
			GetUserObjectInformation(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, b, 4098 * 2, &a);
			swprintf_s(ou, L"|||||||||| %s \n", b);
			wprintf(L"|||||||||| %s \n", b);
			WriteFile(test, ou, wcslen(ou) *sizeof(wchar_t), &a, NULL);
		}
		//ExitProcess(0);
		Sleep(6000);

		/// Test 1 - Try to open a file in an authorizely.
		SetLastError(0);
		HANDLE test1 = CreateFile(argv[TEST1_INDEX], GENERIC_READ, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
		if (test1 == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
			HandleError(L"TEST 1 PASS", GetLastError());
		}
		else {
			HandleError(L"TEST 1 FAILED", GetLastError());
			return EXIT_FAILURE;
		}

		/// Test 2 - Try to open a windows authorizely.
		SetLastError(0);
		if (!MessageBox(NULL, NULL, NULL, MB_OK) && GetLastError() == ERROR_ACCESS_DENIED)
		{
			HandleError(L"TEST 2 PASS", GetLastError());
		}
		else {
			HandleError(L"TEST 2 FAILED", GetLastError());
			return EXIT_FAILURE;
		}

		// Test 3 - Read from clipboard
		SetLastError(0);
		if (!GetClipboardData(CF_TEXT) && GetLastError() == ERROR_ACCESS_DENIED) {
			HandleError(L"TEST 3 PASS", GetLastError());
		}
		else {
			HandleError(L"TEST 3 FAILED", GetLastError());
			return EXIT_FAILURE;
		}

		// Test 4 - Write to clipboard
		SetLastError(0);
		if (!SetClipboardData(CF_TEXT,NULL) && GetLastError() == ERROR_ACCESS_DENIED) {
			HandleError(L"TEST 4 PASS", GetLastError());
		}
		else {
			HandleError(L"TEST 4 FAILED", GetLastError());
			return EXIT_FAILURE;
		}

		// Test 5 - Write to clipboard
		POINT p = { 0 };
		POINT p2 = { 0 };
		SetLastError(0);
		SetCursorPos(50, 50);
		GetCursorPos(&p);
		if (!(p.x == 50 && p.y == 50))
		{
			HandleError(L"TEST 5 PASS", GetLastError());
		}
		else {
			HandleError(L"TEST 5 FAILED", GetLastError());
			return EXIT_FAILURE;
		}

		// Test 6 - Write to clipboard
		SetLastError(0);
		printf("%d", p.x);
		
		if (!GetCursorPos(&p2)){// && GetLastError() == ERROR_ACCESS_DENIED) {
			HandleError(L"TEST 6 PASS", GetLastError());
			WriteFile(test, L"H:}", 3 * sizeof(wchar_t), &a, NULL);

		}
		else {
			HandleError(L"TEST 6 FAILED", GetLastError());
			WriteFile(test, L"B:((", 4 * sizeof(wchar_t), &a, NULL);
			wchar_t b[100];
			ZeroMemory(b, 100 * sizeof(wchar_t));
			int l = swprintf_s(b, L"%d %d", p.x, p2.x);
			WriteFile(test, b, wcslen(b) * sizeof(wchar_t), &a, NULL);
			return EXIT_FAILURE;
		}
		wchar_t b[100];
		int l = swprintf_s(b, L"%d %d", p.x, p2.x);
		WriteFile(test, b, wcslen(b) * sizeof(wchar_t), &a, NULL);



		
	}

	Sleep(60000);










	/*
	wprintf(L"GOT HERE!!!!\n");
	wprintf(L"111: %s\n", argv[1]);
	Sleep(100);
	HANDLE writePipe;
	HANDLE readPipe;

	HANDLE test;
	swscanf_s(argv[1], L"%p", &writePipe);
	if (writePipe == INVALID_HANDLE_VALUE) {
		printf("\t\tFailed to create Pipe! %d\n", GetLastError());
		return 1;
	}
	swscanf_s(argv[2], L"%p", &readPipe);
	if (readPipe == INVALID_HANDLE_VALUE) {
		printf("\t\tFailed to create Pipe! %d\n", GetLastError());
		return 1;
	}

	swscanf_s(argv[3], L"%p", &test);

	RevertToSelf();
	wprintf(L"%s\n", argv[1]);
	
	wprintf(L" :))))) VVVVVVV %d\n", wcslen(L"C:\\Users\\tomer\\Documents\\visual studio 2015\\Projects\\ATO-HW2\\Debug\\a.txt") * sizeof(wchar_t));
	//HANDLE file1 = CreateFileViaBroker(readPipe, writePipe, L"C:\\Users\\tomer\\Documents\\visual studio 2015\\Projects\\ATO-HW2\\Debug\\a.txt", GENERIC_READ, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
	
	RequestHandler p(NULL, readPipe, writePipe);
	HANDLE file1 = p.CreateFileViaBroker(L"C:\\Users\\tomer\\Documents\\visual studio 2015\\Projects\\ATO-HW2\\Broker\\b.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (file1 == INVALID_HANDLE_VALUE) {
		wprintf(L"\n===========\n");
	}
	else {
		DWORD a;
		WriteFile(test, L"Hi", 2 * sizeof(wchar_t), &a, NULL);
		WriteFile(file1, L"Hi", 2 * sizeof(wchar_t), &a, NULL);
		wprintf(L"]]]]]]]]]]]]]] %d %d %p\n\n", GetLastError(), a,file1);
	}
	wprintf(L" :))))) qqqqqqqqq");
	HANDLE file = CreateFile(L"C:\\bdlog.txt", GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	if (file == INVALID_HANDLE_VALUE && GetLastError() == 5) {
		wprintf(L"\n^^^^^^\n");
	}
	else{
		wprintf(L"\n------\n");
	}
	if (SetCurrentDirectory(L"C:\\")) {
		wprintf(L"\n------\n");
	}
	else {
		wprintf(L"\n^^^^^^\n");
	}
	Sleep(100000);

    return 0;*/
}

