#pragma once
#include <windows.h>


#define UNTRUSTED_INTEGRITY_SID		L"S-1-16-0"
#define LOW_INTEGRITY_LEVEL_SID		L"S-1-16-4096"

#define DESKTOP_ALL (DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW  | DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL | DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | DESKTOP_WRITEOBJECTS | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER)



///<summey>Add a sid for a desktop as deny/allow full access</summery>
///<param name='hdesk'>The desktop handle</param>
///<param name='psid'>pointer to sid to deny/allows</param>
///<param name='ToDenied'>wheter to deny or allows</param>
BOOL AddSidToDesktop(HDESK hdesk, PSID psid, BOOL ToDenied);

///<summery>Get the security attribute of the given handle</summet>
///<<param name='Handle'>the handle</param>
///<<param name='Attributes'>the handle</param>
///<return>True if successed and false otherwise, SetLastError accordingly</return>
BOOL GetSecurityAttributes(__in HANDLE Handle, __out PSECURITY_ATTRIBUTES Attributes);


/// <summary> 
/// This function creates a new process that inherited only 
/// a selected set of handles from the current (parent) process.
/// </summary>
/// <see cref="https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873"/>
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
	__in_ecount(cHandlesToInherit) HANDLE *rgHandlesToInherit);


///<summery>
/// This function store inside ppTokenGroups a pointer to 
/// a dynamicly allocated buffer with all the process groups.
///</summary>
///<param name='hProcToken'>the process handler</param>
///<param name='ppTokenGroups'>a pointer to a TOKEN_GROUPS array</param>
BOOL GetTokenGroups(
	__in	HANDLE hProcToken,
	__out	PTOKEN_GROUPS* ppTokenGroups);


///<summery>
/// Get the logon SID and convert it to SID string
///</summery>
///<param name='hToken'>The process token</param>
///<param name='ppSid'>a pointer to a SID pointer</param>
BOOL GetLogonSID(
	__in	HANDLE hToken,
	__out	PSID* ppSid);

///<summery>
/// Set untrusted integirity level for the given token.
///</summery>
///<param name='hToken'>The access token</param>
BOOL SetUntrustedIntegrityLevel(__in HANDLE hToken);

///<summery>
/// Set low integirity level for the given token.
///</summery>
///<param name='hToken'>The access token</param>
BOOL SetLowIntegrityLevel(__in HANDLE hToken);

///<summery>
/// Set a given integirity level for the given token.
///</summery>
///<param name='hToken'>The access token</param>
///<param name='integritySid'>The integrity level string</param>
BOOL SetIntegrityLevel(__in LPCTSTR integritySid, __in HANDLE hToken);