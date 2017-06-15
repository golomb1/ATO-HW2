#pragma once
#include <Windows.h>
#include <wchar.h>
#include <streambuf>

#define MAX_BUFFER	1024 

typedef HANDLE(WINAPI * CreateFileW_Orign)(LPCTSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI * CreateDirectory_Origin)(LPCTSTR, LPSECURITY_ATTRIBUTES);

bool patchIAT(__in HMODULE module, __in PSTR ImportedModuleName, __in PSTR ImportedProcName, __in PVOID alternativeProc, __out_opt PVOID* oldProcAddress);
