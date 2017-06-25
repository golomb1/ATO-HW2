#include "stdafx.h"
#include "Utils.h"
#include <stdio.h>
#include <assert.h>
#include <AclAPI.h>
#include <Sddl.h>
#include <malloc.h>
#include "ErrorMessage.h"


/*


BOOL AddTheAceWindowStation(HWINSTA hwinsta, PSID psid)
{
ACCESS_ALLOWED_ACE   *pace = 0;
ACL_SIZE_INFORMATION aclSizeInfo;
BOOL  bDaclExist;
BOOL  bDaclPresent;
BOOL  bSuccess = FALSE; // assume function will fail
DWORD dwNewAclSize;
DWORD dwSidSize = 0;
DWORD dwSdSizeNeeded;
PACL  pacl;
PACL  pNewAcl =0;
PSECURITY_DESCRIPTOR psd = NULL;
PSECURITY_DESCRIPTOR psdNew = NULL;
PVOID pTempAce;
SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
unsigned int      i;

__try
{
// obtain the dacl for the windowstation,
// retrieves security information for the specified user object.
if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded))
if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
{
psd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
if (psd == NULL)
{
wprintf(L"  HeapAlloc() for psd failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  Heap allocation for psd is OK!\n");

psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
if (psdNew == NULL)
{
wprintf(L"  HeapAlloc() for psdNew failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  Heap allocation for psdNew is OK!\n");

dwSidSize = dwSdSizeNeeded;
if (!GetUserObjectSecurity(hwinsta, &si, psd, dwSidSize, &dwSdSizeNeeded))
{
wprintf(L"  GetUserObjectSecurity() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  GetUserObjectSecurity() should be fine!\n");
}
else
__leave;

// create a new dacl
if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION))
{
wprintf(L"  InitializeSecurityDescriptor() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  InitializeSecurityDescriptor() is nothing wrong!\n");

// get dacl from the security descriptor
if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist))
{
wprintf(L"  GetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  GetSecurityDescriptorDacl() is working!\n");

// initialize
ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
aclSizeInfo.AclBytesInUse = sizeof(ACL);

// call only if the dacl is not NULL
if (pacl != NULL)
{
// get the file ACL size info
if (!GetAclInformation(
pacl,
(LPVOID)&aclSizeInfo,
sizeof(ACL_SIZE_INFORMATION),
AclSizeInformation))
{
wprintf(L"  GetAclInformation() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  Woww... GetAclInformation() is working!\n");
}

// compute the size of the new acl
dwNewAclSize = aclSizeInfo.AclBytesInUse + (2 * sizeof(ACCESS_ALLOWED_ACE)) + (2 * GetLengthSid(psid)) - (2 * sizeof(DWORD));
// allocate memory for the new acl
pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
if (pNewAcl == NULL)
{
wprintf(L"  Heap allocation for pNewAcl failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  Heap allocation for pNewAcl is OK!\n");

// initialize the new dacl
if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
{
wprintf(L"  InitializeAcl() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  InitializeAcl() is pretty damn OK!\n");

// if DACL is present, copy it to a new DACL
if (bDaclPresent) // only copy if DACL was present
{
// copy the ACEs to our new ACL
if (aclSizeInfo.AceCount)
{
for (i = 0; i < aclSizeInfo.AceCount; i++)
{
// get an ACE
if (!GetAce(pacl, i, &pTempAce))
{
wprintf(L"  GetAce() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  GetAce() is OK!\n");

// add the ACE to the new ACL
if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize))
{
wprintf(L"  AddAce() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  AddAce() is OK!\n");
}
}
}

// add the first ACE to the windowstation
pace = (ACCESS_ALLOWED_ACE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));

if (pace == NULL)
{
wprintf(L"  Heap allocation for pace failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  Heap allocation for pace is OK!\n");

pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
pace->Header.AceFlags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE;
pace->Header.AceSize = (WORD)(sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) - sizeof(DWORD));
pace->Mask = GENERIC_ALL;

if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
{
wprintf(L"  CopySid() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  CopySid() is pretty fine!\n");

if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize))
{
wprintf(L"  AddAce() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  AddAce() 1 is pretty fine!\n");

// add the second ACE to the windowstation
pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
pace->Mask = GENERIC_ALL;

if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, (LPVOID)pace, pace->Header.AceSize))
{
wprintf(L"  AddAce() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  AddAce() 2 is pretty fine!\n");

// set new dacl for the security descriptor
if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE))
{
wprintf(L"  SetSecurityDescriptorDacl() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  SetSecurityDescriptorDacl() is pretty fine!\n");

// set the new security descriptor for the windowstation
if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
{
wprintf(L"  SetUserObjectSecurity() failed, error %d\n", GetLastError());
__leave;
}
else
wprintf(L"  SetUserObjectSecurity() is pretty fine!\n");

// indicate success
bSuccess = TRUE;
}
__finally
{
// free the allocated buffers
wprintf(L"  Freeing up all the allocated buffers...\n");
if (pace != NULL)
HeapFree(GetProcessHeap(), 0, (LPVOID)pace);
if (pNewAcl != NULL)
HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);
if (psd != NULL)
HeapFree(GetProcessHeap(), 0, (LPVOID)psd);
if (psdNew != NULL)
HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
}
return bSuccess;
}

*/


BOOL AddSidToDesktop(HDESK hdesk, PSID psid, BOOL ToDenied)
{
	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL                 bDaclExist;
	BOOL                 bDaclPresent;
	BOOL                 bSuccess = FALSE;	// assume function will
											// fail
	DWORD                dwNewAclSize;
	DWORD                dwSidSize = 0;
	DWORD                dwSdSizeNeeded;
	PACL                 pacl;
	PACL                 pNewAcl = nullptr;
	PSECURITY_DESCRIPTOR psd = nullptr;
	PSECURITY_DESCRIPTOR psdNew = nullptr;
	PVOID                pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int         i;

	__try
	{
		/// obtain the security descriptor for the desktop object
		if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				if (psd == nullptr) {
					SetError(L"Could not allocate memory for desktop security descriptor.", GetLastError());
					__leave;
				}
				psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(), HEAP_ZERO_MEMORY, dwSdSizeNeeded);
				if (psdNew == nullptr) {
					SetError(L"Could not allocate memory for copy of desktop security descriptor.", GetLastError());
					__leave;
				}

				dwSidSize = dwSdSizeNeeded;
				if (!GetUserObjectSecurity(hdesk, &si, psd, dwSidSize, &dwSdSizeNeeded)) {
					SetError(L"Could not get the desktop security descriptor.", GetLastError());
					__leave;
				}
			}
			else {
				SetError(L"Could not get the desktop security descriptor.", GetLastError());
				__leave;
			}
		}

		/// create a new security descriptor
		if (!InitializeSecurityDescriptor(psdNew, SECURITY_DESCRIPTOR_REVISION)) {
			SetError(L"Could not initilize security descriptor for revision.", GetLastError());
			__leave;
		}

		/// obtain the dacl from the security descriptor
		if (!GetSecurityDescriptorDacl(psd, &bDaclPresent, &pacl, &bDaclExist)) {
			SetError(L"Could not get desktop dacl.", GetLastError());
			__leave;
		}

		/// initialize
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		/// call only if NULL dacl
		if (pacl == nullptr)
		{
			/// determine the size of the ACL info 
			if (!GetAclInformation(pacl, (LPVOID)&aclSizeInfo,
				sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
				SetError(L"Could not extract ACL infromation size.", GetLastError());
				__leave;
			}
		}

		DWORD sidLength = GetLengthSid(psid);
		/// compute the size of the new acl
		dwNewAclSize = aclSizeInfo.AclBytesInUse +
			sizeof(ACCESS_DENIED_ACE) +
			sidLength -
			sizeof(DWORD);

		/// allocate buffer for the new acl
		pNewAcl = (PACL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwNewAclSize);
		if (pNewAcl == nullptr) {
			SetError(L"Could not allocate ACL for deny.", GetLastError());
			__leave;
		}
		/// initialize the new acl
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION)) {
			SetError(L"Could not initialize Acl.", GetLastError());
			__leave;
		}

		/// If DACL is present, copy it to a new DACL
		/// Only copy if DACL was present
		if (bDaclPresent) {
			/// copy the ACEs to our new ACL
			if (aclSizeInfo.AceCount)
			{
				for (i = 0; i < aclSizeInfo.AceCount; i++)
				{
					/// get an ACE
					if (!GetAce(pacl, i, &pTempAce)) {
						SetError(L"Could not get ACE.", GetLastError());
						__leave;
					}
					/// add the ACE to the new ACL
					if (!AddAce(pNewAcl, ACL_REVISION, MAXDWORD, pTempAce, ((PACE_HEADER)pTempAce)->AceSize)) {
						SetError(L"Could not add ACE.", GetLastError());
						__leave;
					}
				}
			}
		}

		/// add the new ace to the dacl
		if (ToDenied) {
			if (!AddAccessDeniedAce(pNewAcl, ACL_REVISION, DESKTOP_ALL, psid)) {
				SetError(L"Could not add the new ACE.", GetLastError());
				__leave;
			}
		}
		else
		{
			if (!AddAccessAllowedAce(pNewAcl, ACL_REVISION, DESKTOP_ALL, psid)) {
				SetError(L"Could not add the new ACE.", GetLastError());
				__leave;
			}
		}

		/// set new dacl to the new security descriptor 
		if (!SetSecurityDescriptorDacl(psdNew, TRUE, pNewAcl, FALSE)) {
			SetError(L"Could not set the new ace in the security descriptor.", GetLastError());
			__leave;
		}

		ULONG cb = MAX_SID_SIZE;
		PSID UntrustedSid = (PSID)alloca(MAX_SID_SIZE);
		CreateWellKnownSid(WinLowLabelSid, nullptr, UntrustedSid, &cb);
		PACL Sacl = (PACL)alloca(cb += sizeof(ACL) + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
		InitializeAcl(Sacl, cb, ACL_REVISION);
		AddMandatoryAce(Sacl, ACL_REVISION, 0, 0, UntrustedSid);
		SetSecurityDescriptorSacl(&psdNew, TRUE, Sacl, FALSE);

		/// set the new security descriptor for the desktop object
		if (!SetUserObjectSecurity(hdesk, &si, psdNew)) {
			SetError(L"Could not update the desktop's security descriptor.", GetLastError());
			__leave;
		}
		/// indicate success
		bSuccess = TRUE;
	}
	__finally
	{
		/// free buffers
		if (pNewAcl != nullptr)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != nullptr)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != nullptr)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}
	return bSuccess;
}


BOOL GetSecurityAttributes(__in HANDLE Handle, __out PSECURITY_ATTRIBUTES Attributes){
	if (Attributes == nullptr) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	Attributes->bInheritHandle = FALSE;
	Attributes->nLength = sizeof(SECURITY_ATTRIBUTES);

	PACL dacl = nullptr;
	DWORD result = GetSecurityInfo(
		Handle,
		SE_WINDOW_OBJECT,
		DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl,
		nullptr, &Attributes->lpSecurityDescriptor);
	if (ERROR_SUCCESS == result) {
		return TRUE;
	}
	return FALSE;
}


BOOL CreateProcessAsUserWithExplicitHandles(
	__in		 HANDLE hToken,
	__in_opt     LPCTSTR lpApplicationName,
	__inout_opt  LPTSTR lpCommandLine,
	__in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	__in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	__in         BOOL bInheritHandles,
	__in         DWORD dwCreationFlags,
	__in_opt     LPVOID lpEnvironment,
	__in_opt     LPCTSTR lpCurrentDirectory,
	__in         LPSTARTUPINFO lpStartupInfo,
	__out        LPPROCESS_INFORMATION lpProcessInformation,
	__in         DWORD numOfHandlesToInherit,
	__in_ecount(cHandlesToInherit) HANDLE *rgHandlesToInherit)
{
	BOOL fInitialized = FALSE;
	SIZE_T size = 0;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = nullptr;

	BOOL fSuccess = numOfHandlesToInherit < 0xFFFFFFFF / sizeof(HANDLE) &&
		lpStartupInfo->cb == sizeof*lpStartupInfo;
	if (!fSuccess) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (fSuccess) {
		fSuccess = InitializeProcThreadAttributeList(nullptr, 1, 0, &size) ||
			GetLastError() == ERROR_INSUFFICIENT_BUFFER;
	}
	if (fSuccess) {
		lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>
			(HeapAlloc(GetProcessHeap(), 0, size));
		fSuccess = lpAttributeList != nullptr;
	}
	if (fSuccess) {
		fSuccess = InitializeProcThreadAttributeList(lpAttributeList,
			1, 0, &size);
	}
	if (fSuccess) {
		fInitialized = TRUE;
		fSuccess = UpdateProcThreadAttribute(lpAttributeList,
			0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
			rgHandlesToInherit,
			numOfHandlesToInherit * sizeof(HANDLE), nullptr, nullptr);
	}
	if (fSuccess) {
		STARTUPINFOEX info;
		ZeroMemory(&info, sizeof info);
		info.StartupInfo = *lpStartupInfo;
		info.StartupInfo.cb = sizeof info;
		info.lpAttributeList = lpAttributeList;
		fSuccess = CreateProcessAsUser(hToken, lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags | EXTENDED_STARTUPINFO_PRESENT,
			lpEnvironment,
			lpCurrentDirectory,
			&info.StartupInfo,
			lpProcessInformation);
	}

	if (fInitialized) DeleteProcThreadAttributeList(lpAttributeList);
	if (lpAttributeList) HeapFree(GetProcessHeap(), 0, lpAttributeList);
	return fSuccess;
}


BOOL GetTokenGroups(
	__in	HANDLE hProcToken, 
	__out	PTOKEN_GROUPS* ppTokenGroups)
{
	DWORD bufsize = 0;
	DWORD bufsize2 = 0;
	/// Never trust anything from the user
	if (ppTokenGroups == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/// We need to allocate a buffer for the groups, 
	if (GetTokenInformation(hProcToken, TokenGroups, nullptr, 0, &bufsize) || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return FALSE;
	}
	
	*ppTokenGroups = (TOKEN_GROUPS*)GlobalAlloc(GPTR, bufsize);
	if (*ppTokenGroups == nullptr)
	{
		return FALSE;
	}
	return GetTokenInformation(hProcToken, TokenGroups, *ppTokenGroups, bufsize, &bufsize2);
}





BOOL GetLogonSID(
	__in	HANDLE hToken, 
	__out	PSID* ppSid)
{
	DWORD dwLength = 0;
	PTOKEN_GROUPS ptgrp = nullptr;
	
	/// Get the required buffer size and allocate the TOKEN_GROUPS buffer.
	if (!GetTokenInformation(
		hToken,					/// handle to the access token
		TokenGroups,			/// get information about the token's groups
		(LPVOID)ptgrp,			/// pointer to TOKEN_GROUPS buffer
		0,                      /// size of buffer
		&dwLength				/// receives required buffer size
	))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			/// allocate buffer, re-allocate...
			ptgrp = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwLength);
		}
		if (ptgrp == nullptr)
		{
			SetError(L"Failed to allocate heap for process's groups", GetLastError());
			return FALSE;
		}
	}

	ZeroMemory(ptgrp, dwLength);
	/// Get the token group information from the access token.
	if (!GetTokenInformation(
		hToken,				/// handle to the access token
		TokenGroups,		/// get information about the token's groups
		(LPVOID)ptgrp,		/// pointer to TOKEN_GROUPS buffer
		dwLength,			/// size of buffer
		&dwLength			/// receives required buffer size
	))
	{
		SetError(L"Could not load process groups", GetLastError());
		return FALSE;
	}

	/// Loop through the groups to find the logon SID.
	for (DWORD dwIndex = 0; dwIndex < ptgrp->GroupCount; dwIndex++) {
		if ((ptgrp->Groups[dwIndex].Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID)
		{
			dwLength = GetLengthSid(ptgrp->Groups[dwIndex].Sid);
			*ppSid = (PSID)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
			if (*ppSid == nullptr) {
				SetError(L"Failed to allocate memory for the SID", GetLastError());
				return FALSE;
			}
			if (!CopySid(dwLength, *ppSid, ptgrp->Groups[dwIndex].Sid))  // Source
			{
				SetError(L"Failed to copy the SID", GetLastError());
				return FALSE;
			}
			break;
		}
	}
	return TRUE;
}


BOOL SetUntrustedIntegrityLevel(__in HANDLE hToken) {
	return SetIntegrityLevel(UNTRUSTED_INTEGRITY_SID, hToken);
}

BOOL SetLowIntegrityLevel(__in HANDLE hToken) {
	return SetIntegrityLevel(LOW_INTEGRITY_LEVEL_SID, hToken);
}

BOOL SetIntegrityLevel(__in LPCTSTR integritySid, __in HANDLE hToken) {
	PSID pIntegritySid = nullptr;
	TOKEN_MANDATORY_LABEL tml;

	if (!ConvertStringSidToSid(integritySid, &pIntegritySid)) {
		SetError(L"Could not find integrity sid", GetLastError());
		return FALSE;
	}

	ZeroMemory(&tml, sizeof(TOKEN_MANDATORY_LABEL));
	tml.Label.Attributes = SE_GROUP_INTEGRITY;
	tml.Label.Sid = pIntegritySid;

	if (!SetTokenInformation(hToken,TokenIntegrityLevel, &tml,
		sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid))) 
	{
		SetError(L"Could not change token integrity", GetLastError());
		return FALSE;
	}
	return TRUE;
}