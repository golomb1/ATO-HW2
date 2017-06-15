#pragma once
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <Sddl.h>
#include <aclapi.h>
#include "Utils.h"
#include "ErrorMessage.h"
#include "RemoteUtils.h"

#define RESTRICTED_SID					L"S-1-5-12"
#define USERS_SID						L"S-1-5-32-545"
#define LOW_INTEGRITY_LEVEL_SID			L"S-1-16-4096"

typedef struct {
	HANDLE read;
	HANDLE write;
} DataToChild;


typedef struct {
	PCHAR	FunctionNameInDll;
	DWORD	FunctionOrdinalInDll;
	BOOL	FunctionIsOrdinal;
} DLLFunction;



///<summery>Create a dicretory with untrusted mandatory level.</summery>
BOOL CreateUntrustedFolder(__in LPCWSTR DirectoryName);


///<summery>Set the integrity of a given process as untrusted</summery>
///<param name='hProcess'>The handle for the process that need to be untrusted</param>
///<return>NO_ERROR if successed, or Error value otherwise</return>
ULONG SetProcessUntrusted(__in HANDLE hProcess);


///<summery>
///	This function create the sandbox process's job 
/// with the appropriate restrictions.
///</summery>
HANDLE CreateRestrictedJobObject();

///<summery>
/// Create a process with restricted access token and permissions.
///	To achieve that, the process starts with the initialization token,
/// and after loading, switch to lower permissions.
///</summery>
///<param name='InitilizationToken'>token for intilization process</param>
///<param name='PrimaryToken'>process's token</param>
///<param name='DesktopName'>The desktop name that the process will be executed in, 
///				this function create it if it doesn't exist</param>
///<param name='NumOfInheritedHandles'>the number of handles to inherited by the restricted process</param>
///<param name='InheritedHandles'>handles to inherited by the restricted process</param>
///<param name='AppPath'>the path for the new process executable</param>
///<param name='CommandLine'>command line for the new process</param>
///<param name='Directory'>The home directory for the process</param>
///<param name='DllPath'>command line for the new process</param>
///<param name='DllPathLength'>the length of the dll path.</param>
///<param name='Entry'>the function that hook the entry point.</param>
///<param name='SetParam'>the function that accept the parameters (@param ChildData).</param>
///<param name='ChildData'>parameters to send to the dll.</param>
///<param name='ProcInfo'>struct that hold the new process information</param>
BOOL CreateRestrictedProcess(
	__in		HANDLE			PrimaryToken,
	__in		HANDLE			InitilizationToken,
	__in		PWCHAR			DesktopName,
	__in		DWORD			NumOfInheritedHandles,
	__in_opt	PHANDLE			InheritedHandles,
	__in		PWCHAR			AppPath,
	__in		PWCHAR			CommandLine,
	__in		PWCHAR			Directory,
	__in		PWCHAR			DllPath,
	__in		DWORD			DllPathLength, 
	__in		DLLFunction		Entry,
	__in		DLLFunction		SetParam,
	__in		DataToChild		ChildData,
	__out		PPROCESS_INFORMATION ProcInfo);


///<summery>Hook the entry point of a process that generated the ProcInfo structure, 
/// with a function named @param NewEntryName in the dll: @param DllPath.
///</summery>
///<param name='ProcInfo'>the process information.</param>
///<param name='ChildData'>parameters to send to the dll.</param>
///<param name='DllPath'>the path to the dll file.</param>
///<param name='DllPathSize'>the length of the dll path.</param>
///<param name='SetParam'>the function that accept the parameters (@param ChildData).</param>
///<param name='Entry'>the function that hook the entry point.</param>
///<param name='InitilizationToken'>A token for initilization of new thread 
/// with higher permission (imperssonate).
/// </param>
BOOL LoadNewEntry(
	__in		PPROCESS_INFORMATION	ProcInfo,
	__in		DataToChild				ChildData,
	__in		PWCHAR					DllPath,
	__in		DWORD					DllPathSize,
	__in		DLLFunction				SetParam,
	__in		DLLFunction				Entry,
	__in		HANDLE					InitilizationToken);

///<summery>
/// Fill the SidToDisable arguemnt according to the requested policy:
/// Full restriction want to only keep the SID LOGON.
/// Not full restriction will keep LOGON, EVERYONE and BUILTIN/USERS SIDs.
///</summery>
///<param name='SidsToDisable'>a buffer to be filled</param>
///<param name='Bufsize'>the SidsToDisable buffer's size</param>
///<param name='pTokenGroups'>The list of groups</param>
///<param name='FullRestriction'> indicate the requested policy</param>
///<return>The number of SID to disable, or ~0 in case of failure.</return>
DWORD GetSidsToDisable(
	__out	PSID_AND_ATTRIBUTES SidsToDisable,
	__in	DWORD Bufsize,
	__in	PTOKEN_GROUPS pTokenGroups,
	__in	BOOL FullRestriction);


///<summery>
/// If the current user is an admin, the owner will be 
/// administrators - this might not be a good thing
/// we add both System & the User SID to the DACL of the token.
///</summery>
///<param name='hToken'>The process token</param>
BOOL TweakToken(HANDLE hToken);


///<summery>
/// Create restricted token according to the requested policy.
/// If in Full Restriction, then the token include only RESTRICTED and LOGON sids.
/// Otherwise, the token also include BUILTIN/USERS & EVERYONE.
///</summery>
///<param name='FullRestriction'>The restriction policy.</param>
HANDLE RestrictProcessToken(BOOL FullRestriction);