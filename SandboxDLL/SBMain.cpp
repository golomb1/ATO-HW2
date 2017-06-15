#include "stdafx.h"
#include "SBMain.h"

#define pointerFromRVA(base, rvd) (((char*)base)+((int)rvd))



DWORD GetEntryPoint2(__in HMODULE module) {
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)pointerFromRVA(module, dosHeader->e_lfanew);
	return (ntHeader->OptionalHeader).AddressOfEntryPoint;
}


void SBMain() {
	printf("Hi :) * 8\n");
	
	ExitProcess(0);
	//DWORD entry = GetEntryPoint2(GetModuleHandle(NULL));
	//((void(*)(void))entry)();
}