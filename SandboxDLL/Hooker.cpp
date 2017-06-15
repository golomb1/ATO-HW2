#include "stdafx.h"
#include "Hooker.h"


#define pointerFromRVA(base, rvd) (((char*)base)+((int)rvd))

bool patchIAT(__in HMODULE module, __in PSTR ImportedModuleName, __in PSTR ImportedProcName, __in PVOID alternativeProc, __out_opt PVOID* oldProcAddress)
{
	int i;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)pointerFromRVA(module, dosHeader->e_lfanew);

	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		OutputDebugStringA("The process doesnt have NT signature, failed....");
		return false;
	}
	IMAGE_DATA_DIRECTORY importDataDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)pointerFromRVA(module, importDataDirectory.VirtualAddress);

	// iterate on the all the dll that was imported
	for (i = 0; importDescriptor[i].Characteristics != 0; i++)
	{
		PSTR dllName = (PSTR)pointerFromRVA(module, importDescriptor[i].Name);
		if (_strcmpi(dllName, ImportedModuleName) == 0)
		{
			// we found the dll we want
			PIMAGE_THUNK_DATA Thunk;
			PIMAGE_THUNK_DATA OrigThunk;
			if (!importDescriptor[i].FirstThunk || !importDescriptor[i].OriginalFirstThunk)
			{
				OutputDebugString(TEXT("FirstThunk is null!, failed..."));
				return false;
			}

			Thunk = (PIMAGE_THUNK_DATA)pointerFromRVA(module, importDescriptor[i].FirstThunk);
			OrigThunk = (PIMAGE_THUNK_DATA)pointerFromRVA(module, importDescriptor[i].OriginalFirstThunk);

			while (OrigThunk->u1.Function != NULL)
			{
				if (!(OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
				{
					PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)
						pointerFromRVA(module, OrigThunk->u1.AddressOfData);
					if (_strcmpi(ImportedProcName, (char*)import->Name) == 0)
					{
						// found it!!!!
						// now we need to patch it!!!
						DWORD junk;
						MEMORY_BASIC_INFORMATION thunkMemInfo;
						// save the page memory protection in order to restore it later.
						VirtualQuery(Thunk, &thunkMemInfo, sizeof(MEMORY_BASIC_INFORMATION));
						// Change page memory protection to writble.
						if (!VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &thunkMemInfo.Protect))
						{
							OutputDebugStringA("VirtualProtected to set permission failed! ERROR: " + GetLastError());
							return false;
						}

						//
						// Replace function pointers (non-atomically).
						//
						if (!oldProcAddress)
						{
							*oldProcAddress = (PVOID)Thunk->u1.Function;
						}
						Thunk->u1.Function = (DWORD)(DWORD_PTR)alternativeProc;
						//
						// Restore page protection.
						//
						if (!VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, thunkMemInfo.Protect, &junk))
						{
							OutputDebugStringA("VirtualProtected to restore permission failed! ERROR: " + GetLastError());
							return false;
						}
					}
				}
				OrigThunk++;
				Thunk++;
			}
		}
	}
	return true;
}
