#include "stdafx.h"
#include "RestrictedProcess.h"
#include <stdio.h>
#include <assert.h>
#include <Sddl.h>
#include <aclapi.h>
#include "Utils.h"
#include "ErrorMessage.h"
#include "RemoteUtils.h"


BOOL CreateUntrustedFolder(__in LPCWSTR DirectoryName)
{
	ULONG cb = MAX_SID_SIZE;
	PSID UntrustedSid = (PSID)alloca(MAX_SID_SIZE);
	if (CreateWellKnownSid(WinUntrustedLabelSid, nullptr, UntrustedSid, &cb))
	{
		PACL Sacl = (PACL)alloca(cb += sizeof(ACL) + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
		InitializeAcl(Sacl, cb, ACL_REVISION);
		if (AddMandatoryAce(Sacl, ACL_REVISION, 0, 0, UntrustedSid))
		{
			SECURITY_ATTRIBUTES sa;
			SECURITY_DESCRIPTOR sd;
			InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
			SetSecurityDescriptorSacl(&sd, TRUE, Sacl, FALSE);
			sa.lpSecurityDescriptor = &sd;
			sa.bInheritHandle = TRUE;
			sa.nLength = sizeof sa;
			return CreateDirectory(DirectoryName, &sa);
		}
	}
	return FALSE;
}



ULONG SetProcessUntrusted(__in HANDLE hProcess)
{
	TOKEN_MANDATORY_LABEL tml = { { (PSID)alloca(MAX_SID_SIZE), SE_GROUP_INTEGRITY } };
	ULONG cb = MAX_SID_SIZE;
	HANDLE hToken;
	if (!CreateWellKnownSid(WinUntrustedLabelSid, nullptr, tml.Label.Sid, &cb)) {
		SetError(L"Could not create untrusted sid.", GetLastError());
		return GetLastError();
	}
	if(!OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT, &hToken))
	{
		SetError(L"Could not open the process token.", GetLastError());
		return GetLastError();
	}
	ULONG dwError = NOERROR;
	if (!SetTokenInformation(hToken, TokenIntegrityLevel, &tml, sizeof tml))
	{
		SetError(L"Could not set mandatory level.", GetLastError());
		return GetLastError();
	}
	CloseHandle(hToken);
	return dwError;
}


HANDLE CreateRestrictedJobObject() {
	/// Local variables, initilization is near use.
	int err;
	SECURITY_ATTRIBUTES security_attributes;
	JOBOBJECT_BASIC_UI_RESTRICTIONS uiRestriction;
	JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimits;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION extLimit;
	
	/// Create the job Object
	ZeroMemory(&security_attributes, sizeof(SECURITY_ATTRIBUTES));
	security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	security_attributes.bInheritHandle = FALSE;
	HANDLE job = CreateJobObject(&security_attributes, nullptr);
	if (!job) {
		SetError(L"Could not create job object", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	/// Add UI restriction
	ZeroMemory(&uiRestriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DESKTOP;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_DISPLAYSETTINGS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_EXITWINDOWS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_HANDLES;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_READCLIPBOARD;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
	uiRestriction.UIRestrictionsClass |= JOB_OBJECT_UILIMIT_GLOBALATOMS;
	if (!SetInformationJobObject(job, JobObjectBasicUIRestrictions, &uiRestriction, sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS))) {
		err = GetLastError();
		SetError(L"Could not restrict ui for the job object", err);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	/// Restrict information
	ZeroMemory(&basicLimits, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	basicLimits.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	/// Limit to single process.
	basicLimits.ActiveProcessLimit = 1;

	ZeroMemory(&extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
	extLimit.BasicLimitInformation = basicLimits;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &extLimit, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
		err = GetLastError();
		SetError(L"Could not restrict information for the job object", err);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}
	return job;
}

BOOL ExecuteRemoteThreadBeforeInitilization(
	__in	HANDLE					processHandle, 
	__in	DWORD					paramSize, 
	__in	PVOID					param, 
	__in	LPTHREAD_START_ROUTINE	function, 
	__in	HANDLE					InitilizationToken,
	__out	PDWORD					phLibModule)
{
	HANDLE baseAddress = VirtualAllocEx(processHandle, nullptr, paramSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (baseAddress == INVALID_HANDLE_VALUE) {
		SetError(L"Could not allocate memory remotly.", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(processHandle, baseAddress, param, paramSize, nullptr)) {
		SetError(L"Could not write paramters remotly.", GetLastError());
		return FALSE;
	}

	HANDLE threadHandle = CreateRemoteThread(
		processHandle,
		nullptr,
		0,
		function,
		baseAddress,
		CREATE_SUSPENDED,
		nullptr);
	if (threadHandle == INVALID_HANDLE_VALUE) {
		SetError(L"Could not create thread remotly.", GetLastError());
		return FALSE;
	}
	if (!SetThreadToken(&threadHandle, InitilizationToken)) {
		SetError(L"Could not change remote thread token.", GetLastError());
		return FALSE;
	}
	ResumeThread(threadHandle);
	WaitForSingleObject(threadHandle, INFINITE);

	// should be STILL_ACTIVE 
	DWORD processExitCode = 0;
	GetExitCodeProcess(processHandle, &processExitCode);

	/// Get handle of the loaded module
	if (!GetExitCodeThread(threadHandle, phLibModule) || processExitCode != STILL_ACTIVE) {
		SetError(L"Could not get remote thread exit code.", GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL LoadNewEntry(
	__in		PPROCESS_INFORMATION	ProcInfo,
	__in		DataToChild				ChildData,
	__in		PWCHAR					DllPath,
	__in		DWORD					DllPathSize,
	__in		DLLFunction				SetParam,
	__in		DLLFunction				Entry,
	__in		HANDLE					InitilizationToken)
{

	/// Part 1 - Inject sandbox dll
	CONTEXT thread_context;
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (*ProcInfo).dwProcessId);
	if (processHandle == nullptr)
	{
		SetError(L"Could not open current process.", GetLastError());
		return FALSE;
	}
	HMODULE dllHandle = GetModuleHandle(L"Kernel32.dll");
	if (dllHandle == nullptr)
	{
		SetError(L"Could not open kernel32 dll.", GetLastError());
		return FALSE;
	}
	
	HANDLE loadLibraryAddress = GetProcAddress(dllHandle, "LoadLibraryW");
	if (loadLibraryAddress == nullptr)
	{
		SetError(L"Could not find LoadLibraryW.", GetLastError());
		return FALSE;
	}

	DWORD hLibModule = 0;
	if (!ExecuteRemoteThreadBeforeInitilization(
		processHandle, DllPathSize, DllPath,
		(LPTHREAD_START_ROUTINE)loadLibraryAddress, InitilizationToken, &hLibModule)) {
		return FALSE;
	}

	/// Part 2 - give handle values to childprocess

	FARPROC setParamFunc = GetRemoteProcAddress(
		processHandle,
		(HMODULE)hLibModule,
		SetParam.FunctionNameInDll,
		SetParam.FunctionOrdinalInDll,
		SetParam.FunctionIsOrdinal);

	DWORD successed = 0;
	if (!ExecuteRemoteThreadBeforeInitilization(
		processHandle, sizeof(DataToChild), &ChildData,
		(LPTHREAD_START_ROUTINE)setParamFunc, InitilizationToken, &successed)) {
		return FALSE;
	}


	/// Part 3 - Start hooking the entry point
	FARPROC newMain = GetRemoteProcAddress(
		processHandle, 
		(HMODULE)hLibModule, 
		Entry.FunctionNameInDll,
		Entry.FunctionOrdinalInDll,
		Entry.FunctionIsOrdinal);
	if (newMain == nullptr) {
		SetError(L"Could not get new main function.", GetLastError());
		return FALSE;
	}
	/// replace the eip register for the main thread
	ZeroMemory(&thread_context, sizeof(CONTEXT));
	thread_context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext((*ProcInfo).hThread, &thread_context)) {
		SetError(L"Could not get main thread context.", GetLastError());
		return FALSE;
	}
	thread_context.Eip = (DWORD)newMain;
	if (!SetThreadContext((*ProcInfo).hThread, &thread_context)) {
		SetError(L"Could notset main thread context.", GetLastError());
		return FALSE;
	}
	return TRUE;
}


BOOL CreateRestrictedProcess(
	__in		HANDLE			PrimaryToken,
	__in		HANDLE			InitilizationToken,
	__in		PWCHAR			DesktopName,
	__in		DWORD			NumOfInheritedHandles,
	__in_opt	PHANDLE			InheritedHandles,
	__in_opt	HANDLE			In,
	__in_opt	HANDLE			Out,
	__in		PWCHAR			AppPath,
	__in		PWCHAR			CommandLine, 
	__in		PWCHAR			Directory,
	__in		PWCHAR			DllPath,
	__in		DWORD			DllPathLength,
	__in		DLLFunction		Entry,
	__in		DLLFunction		SetParam,
	__in		DataToChild		ChildData,
	__out		PPROCESS_INFORMATION ProcInfo)
{
	STARTUPINFO si;
	DWORD flags = NORMAL_PRIORITY_CLASS | CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | STARTF_USESTDHANDLES;

	/// Copy the current desktop security attributes
	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	if (!GetSecurityAttributes(GetProcessWindowStation(), &sa)) {
		SetError(L"Could not get the current windows station security attributes.", GetLastError());
		return FALSE;
	}
	HDESK original_desktop = GetThreadDesktop(GetCurrentThreadId());
	if (original_desktop == nullptr) {
		SetError(L"Could not get the current thread desktop.", GetLastError());
		return FALSE;
	}
	if (!GetSecurityAttributes(original_desktop, &sa)) {
		SetError(L"Could not get the desktop security attributes.", GetLastError());
		CloseHandle(original_desktop);
		return FALSE;
	}

	/// Open a new Desktop in a new Workstation.
	HWINSTA current_winsta = GetProcessWindowStation();
	HWINSTA winsta = CreateWindowStation(nullptr, TRUE, GENERIC_ALL, &sa);
	if (!winsta) {
		winsta = OpenWindowStation(nullptr, TRUE, GENERIC_ALL);
	}
	if (!winsta) {
		SetError(L"Could not create a new windows station.", GetLastError());
		CloseHandle(original_desktop);
		return FALSE;
	}
	if (!SetProcessWindowStation(winsta)) {
		SetError(L"Could not change new windows stations.", GetLastError());
		CloseHandle(original_desktop);
		return FALSE;
	}

	DWORD desktopFlag = GENERIC_READ | DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW;
	HDESK hidden_desktop = OpenDesktop(DesktopName, NULL, TRUE, desktopFlag);
	if (!hidden_desktop)
	{
		hidden_desktop = CreateDesktop(DesktopName, nullptr, nullptr, 0, desktopFlag, &sa);
	}
	if (!hidden_desktop) {
		SetError(L"Could not create new desktop.", GetLastError());
		SetProcessWindowStation(current_winsta);
		CloseHandle(winsta);
		CloseHandle(original_desktop);
		return FALSE;
	}
	
	PWCHAR windowsStationName;
	PWCHAR createdDesktopName;
	DWORD windowsStationNameSize = 0;
	DWORD createdDesktopNameSize = 0;
	if (!GetUserObjectInformation(winsta, UOI_NAME, nullptr, 0, &windowsStationNameSize) && 
			GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		SetError(L"Could not get name of new windows station.", GetLastError());
		CloseHandle(hidden_desktop);
		SetProcessWindowStation(current_winsta);
		CloseHandle(winsta);
		CloseHandle(original_desktop);
		return FALSE;
	}
	if (!GetUserObjectInformation(hidden_desktop, UOI_NAME, nullptr, 0, &createdDesktopNameSize) &&
		GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		SetError(L"Could not get name of new windows station.", GetLastError());
		CloseHandle(hidden_desktop);
		SetProcessWindowStation(current_winsta);
		CloseHandle(winsta);
		CloseHandle(original_desktop);
		return FALSE;
	}

	windowsStationName = new WCHAR[windowsStationNameSize];
	createdDesktopName = new WCHAR[createdDesktopNameSize];
	ZeroMemory(windowsStationName, windowsStationNameSize * sizeof(WCHAR));
	ZeroMemory(createdDesktopName, createdDesktopNameSize * sizeof(WCHAR));

	if (!GetUserObjectInformation(winsta, UOI_NAME, windowsStationName, 
		windowsStationNameSize * sizeof(WCHAR), &windowsStationNameSize))
	{
		SetError(L"Could not get name of new windows station.", GetLastError());
		CloseHandle(hidden_desktop);
		SetProcessWindowStation(current_winsta);
		CloseHandle(winsta);
		CloseHandle(original_desktop);
		return FALSE;
	}
	if (!GetUserObjectInformation(hidden_desktop, UOI_NAME, 
		createdDesktopName, createdDesktopNameSize * sizeof(WCHAR), 
		&createdDesktopNameSize)) 
	{
		SetError(L"Could not get name of new windows station.", GetLastError());
		CloseHandle(hidden_desktop);
		SetProcessWindowStation(current_winsta);
		CloseHandle(winsta);
		CloseHandle(original_desktop);
		return FALSE;
	}

	PWCHAR desktopNameForCreateProcess = new WCHAR[windowsStationNameSize + 1 + createdDesktopNameSize];
	swprintf_s(desktopNameForCreateProcess, windowsStationNameSize + 1 + createdDesktopNameSize, 
		L"%s\\%s", windowsStationName, createdDesktopName);
	delete[] windowsStationName;
	delete[] createdDesktopName;

	/// Finish with the other windows station, return back.
	SetProcessWindowStation(current_winsta);
	
	/// Set the current desktop (the real one) with denied to NULL SID.
	PSID nullSid;
	ConvertStringSidToSid(L"S-1-0-0", &nullSid);
	/*if (!AddSidToDesktop(hidden_desktop, nullSid, FALSE))
	{
		//SetError(L"Could not set new desktop sid.", GetLastError());
		//return FALSE;
	}
	if(!AddSidToDesktop(GetThreadDesktop(GetCurrentThreadId()), nullSid, TRUE))
	{
		SetError(L"Could not set current desktop sid.", GetLastError());
		return FALSE;
	}*/

	/// Create the process
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof si;
	si.lpDesktop  = desktopNameForCreateProcess;
	si.hStdError  = INVALID_HANDLE_VALUE;
	si.hStdInput  = In;
	si.hStdOutput = Out;
	

	HANDLE job = CreateRestrictedJobObject();
	if (job == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	/// Create the process
	if (!CreateProcessAsUserWithExplicitHandles(PrimaryToken, // the process token
		AppPath,				// application path
		CommandLine,			// command line - 1st token is executable
		nullptr,					// default security attirubtes on process
		nullptr,					// default security attributes on thread
		TRUE,					// inherit handles from parent
		flags,					// use normal priority class
		nullptr,					// inherit environment from parent
		Directory,				// use the current directory of parent
		&si,					// pointer to the STARTUPINFO
		ProcInfo ,				// pointer to the PROCESSINFROMATION
		NumOfInheritedHandles,
		InheritedHandles))
	{
		delete[] desktopNameForCreateProcess;
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		return FALSE;
	}
	delete[] desktopNameForCreateProcess;

	/// Assign process to job
	if (!AssignProcessToJobObject(job, (*ProcInfo).hProcess)) {
		SetError(L"Could not assign process to a job", GetLastError());
		TerminateProcess((*ProcInfo).hProcess, EXIT_FAILURE);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		return FALSE;
	}

	/// hook the entry point to add automatic handling of finishing privlliege drop.
	if (!LoadNewEntry(ProcInfo, ChildData, DllPath, 
		DllPathLength, SetParam, Entry, InitilizationToken)) {
		TerminateProcess((*ProcInfo).hProcess, EXIT_FAILURE);
		return FALSE;
	}

	/// Change the process token for initilization.
	if (!SetThreadToken(&(*ProcInfo).hThread, InitilizationToken)) {
		SetError(L"Could not change process's token", GetLastError());
		TerminateProcess((*ProcInfo).hProcess, EXIT_FAILURE);
		TerminateJobObject(job, EXIT_FAILURE);
		CloseHandle(job);
		return FALSE;
	}
	/// Resume the child process.
	ResumeThread((*ProcInfo).hThread);
	return TRUE;
}



DWORD GetSidsToDisable(
	__in	PSID_AND_ATTRIBUTES SidsToDisable,
	__in	DWORD Bufsize,
	__in	PTOKEN_GROUPS pTokenGroups,
	__in	BOOL FullRestriction)
{
	DWORD DisableSidCount = 0;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	/// Firstly check the arguments
	if (SidsToDisable == nullptr || pTokenGroups == nullptr ||
		Bufsize < pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		SetError(L"INVALID_PARAMETER", ERROR_INVALID_PARAMETER);
		return ~0;
	}
	/// Full restriction want to only keep the SID LOGON.
	/// Not full restriction will keep LOGON, EVERYONE and BUILTIN/USERS SIDs.
	
	PSID intr;
	ConvertStringSidToSid(L"S-1-5-4", &intr);
	for (DWORD i = 0; i < pTokenGroups->GroupCount; i++)
	{
		SID* pSid = (SID*)pTokenGroups->Groups[i].Sid;
		if (!FullRestriction) {
			// this could be a large OR statement, but this way is easier to read
			if (EqualSid((PSID)&EveryoneSid, pTokenGroups->Groups[i].Sid)) {
				continue;
			}
			if (EqualSid(intr, pTokenGroups->Groups[i].Sid)) {
				continue;
			}
			if (pSid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID &&
				pSid->SubAuthority[1] == DOMAIN_ALIAS_RID_USERS)
			{
				continue;
			}
		}
		if (pSid->SubAuthorityCount == SECURITY_LOGON_IDS_RID_COUNT &&
			pSid->SubAuthority[0] == SECURITY_LOGON_IDS_RID)
		{
			continue;
		}
		SidsToDisable[DisableSidCount].Sid = pTokenGroups->Groups[i].Sid;
		DisableSidCount++;
	}
	return DisableSidCount;
}



BOOL TweakToken(HANDLE hToken)
{
	/// Local variables
	TOKEN_DEFAULT_DACL TokenDacl;
	DWORD needed;
	SID SystemSid = { 1, 1, SECURITY_NT_AUTHORITY, SECURITY_LOCAL_SYSTEM_RID };
	const DWORD MaxSidSize = sizeof(SID) + (SID_MAX_SUB_AUTHORITIES - 1) * sizeof(DWORD);
	BYTE TokenUserBuf[MaxSidSize];
	BYTE TokenOwnerBuf[MaxSidSize];

	const DWORD DaclBufsize = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) + MaxSidSize - sizeof(DWORD)) * 2;
	BYTE DaclBuf[DaclBufsize];
	
	BYTE AceBuf[sizeof(ACCESS_ALLOWED_ACE) + MaxSidSize - sizeof(DWORD)];
	ACL* pAcl = (ACL*)DaclBuf;

	/// Get relevant data
	if (!GetTokenInformation(hToken, TokenUser, TokenUserBuf, MaxSidSize, &needed)) {
		return FALSE;
	}
	if (!GetTokenInformation(hToken, TokenOwner, TokenOwnerBuf, MaxSidSize, &needed)) {
		return FALSE;
	}
	PSID UserSid = ((TOKEN_USER*)TokenUserBuf)->User.Sid;
	PSID OwnerSid = ((TOKEN_OWNER*)TokenOwnerBuf)->Owner;


	/// If the owner isn't the current user then set the owner as the current user.
	/// Otherwise the process will not be able to access itself.
	if (!EqualSid(UserSid, OwnerSid))
	{
		if (!SetTokenInformation(hToken, TokenOwner, UserSid, MaxSidSize))
		{
			SetError(L"Cannot set token owner", GetLastError());
			return FALSE;
		}
	}
	/// Now let's set the token DACL
	if (!InitializeAcl(pAcl, DaclBufsize, ACL_REVISION))
	{
		SetError(L"Cannot initialize ACL", GetLastError());
		return FALSE;
	}


	DWORD sidlen = GetLengthSid(UserSid);
	/// Create the first ACE for the UserSid
	ACCESS_ALLOWED_ACE * pAce = (ACCESS_ALLOWED_ACE*)AceBuf;
	pAce->Header.AceFlags	= 0;
	pAce->Header.AceType	= 0;
	pAce->Header.AceSize	= (WORD)(sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidlen);
	pAce->Mask				= GENERIC_ALL;
	CopySid(sidlen, (PSID)&pAce->SidStart, UserSid);

	/// Append the pAce to the end
	if (!AddAce(pAcl, ACL_REVISION, ~0, pAce, pAce->Header.AceSize))
	{
		SetError(L"Cannot add User ACE to ACL", GetLastError());
		return FALSE;
	}

	/// Now create the next one - everything is set, so we just change the SID and the size
	pAce->Header.AceSize = (WORD)(sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid((PSID)&SystemSid));
	CopySid(GetLengthSid(&SystemSid), (PSID)&pAce->SidStart, (PSID)&SystemSid);
	if (!AddAce(pAcl, ACL_REVISION, ~0, pAce, pAce->Header.AceSize))
	{
		SetError(L"Cannot add System ACE to ACL", GetLastError());
		return FALSE;
	}

	/// We finish with the creation of the DACL
	TokenDacl.DefaultDacl = pAcl;
	if (!SetTokenInformation(hToken, TokenDefaultDacl, &TokenDacl, pAcl->AclSize))
	{
		SetError(L"Cannot set token DACL", GetLastError());
		return FALSE;
	}
	return TRUE;
}



HANDLE RestrictProcessToken(BOOL FullRestriction)
{
	/// Local variables
	HANDLE RestrictedToken;
	int err;
	int success;
	HANDLE hProcToken;
	TOKEN_GROUPS* pTokenGroups;
	PSID logon;
	DWORD RestrictedCount;
	DWORD bufsize;
	DWORD DisableSidCount;
	SID_AND_ATTRIBUTES* SidsToDisable;
	SID_AND_ATTRIBUTES* restrictedSids;
	SID EveryoneSid = { 1, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	/// Get process token to be used as a base.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcToken))
	{
		SetError(L"Could not open process token", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	/// Extract the token's groups
	if(!GetTokenGroups(hProcToken, &pTokenGroups))
	{	
		CloseHandle(hProcToken);
		return INVALID_HANDLE_VALUE;
	}

	/// Alocate dynamic buffer for the Disable SIDs
	bufsize = pTokenGroups->GroupCount * sizeof(SID_AND_ATTRIBUTES);
	SidsToDisable = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, bufsize);
	if (SidsToDisable == nullptr)
	{
		err = GetLastError();
		SetError(L"Could not allocate memory for disabled sids", err);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);	
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	DisableSidCount = GetSidsToDisable(SidsToDisable, bufsize, pTokenGroups, FullRestriction);
	if (DisableSidCount == ~0)
	{
		err = GetLastError();
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	/// Create Restricted SID
	/// If FullRestriction is n then leave only LOGON & RESTRICTED SIDs, 
	/// otherwise leave LOGON, RESTRICTED, EVERYONE, BUILTIN\USERS SIDs.
	RestrictedCount = FullRestriction ? 3 : 5;
	restrictedSids = (SID_AND_ATTRIBUTES*)GlobalAlloc(GPTR, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	if (restrictedSids == nullptr) {
		err = GetLastError();
		SetError(L"Could not allocate memory for restricted sids", err);
		GlobalFree(SidsToDisable);
		GlobalFree(pTokenGroups);
		CloseHandle(hProcToken);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}
	ZeroMemory(restrictedSids, RestrictedCount * sizeof(SID_AND_ATTRIBUTES));
	ConvertStringSidToSid(RESTRICTED_SID, &restrictedSids[0].Sid);
	GetLogonSID(hProcToken, &logon);
	restrictedSids[1].Sid = logon;
	PSID nullSid;
	ConvertStringSidToSid(L"S-1-0-0", &nullSid); 
	restrictedSids[2].Sid = nullSid;
	if (!FullRestriction) {
		restrictedSids[3].Sid = &EveryoneSid;
		ConvertStringSidToSid(USERS_SID, &restrictedSids[4].Sid);
	}
	
	success = CreateRestrictedToken(hProcToken, /// existing token
			DISABLE_MAX_PRIVILEGE,				/// flags
			DisableSidCount,					/// number of SIDs to disable
			SidsToDisable,						/// array of SID and attributes
			0,									/// number of privileges to drop
			nullptr,							/// array of privileges
			RestrictedCount,					/// no restricted SIDs
			restrictedSids,						/// array of restricted SIDs 
			&RestrictedToken);
	

	err = GetLastError();
	GlobalFree(logon);
	GlobalFree(restrictedSids);
	GlobalFree(SidsToDisable);
	GlobalFree(pTokenGroups);
	if(!success)
	{
		SetError(L"Could not create restricted token", err);
		SetLastError(err);
		return INVALID_HANDLE_VALUE;
	}

	if (FullRestriction) {
		/// Set integrity level to untrusted
		// SetLowIntegrityLevel(RestrictedToken);
		/// Set integrity level to untrusted
		//SetUntrustedIntegrityLevel(RestrictedToken);
	}

	/// If the current user is an admin, the owner will be 
	/// administrators - this might not be a good thing
	if (!TweakToken(RestrictedToken)) {
		return INVALID_HANDLE_VALUE;
	}
	return RestrictedToken;
}