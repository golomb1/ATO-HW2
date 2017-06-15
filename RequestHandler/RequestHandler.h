#pragma once
#include  "PipeIPC.h"

#define		DllExport   __declspec( dllexport )  
#define		NOTIFY_PROCESS_INITLIZATION_COMPLETE	0
#define		CREATE_DIRECTORY_REQUEST_TYPE			1  
#define		CREATE_FILE_REQUEST_TYPE				2
#define		HANDLE_INPUT_REQUEST					3
#define		HANDLE_OUTPUT_REQUEST					4


struct CreateFileRequest {
	DWORD	 NameLength;
	DWORD    dwDesiredAccess;
	DWORD    dwShareMode;
	DWORD	 lpSecurityAttributesLength;
	DWORD    dwCreationDisposition;
	DWORD    dwFlagsAndAttributes;
	HANDLE   hTemplateFile;
};


struct CreateDirectoryRequest {
	DWORD	 NameLength;
	DWORD	 lpSecurityAttributesLength;
};


class DllExport RequestHandler
{
private:
	PipeIPC* IPC;

public:
	RequestHandler(__in_opt PVOID data, __in HANDLE read, __in HANDLE write);
	~RequestHandler();
	VOID SetHandler(__in int index, __in RequestHandle handler);
	BOOL RequestHandler::HandleMessage();

	BOOL NotifyOnInitilizationComplete();
	
	BOOL CreateDirectoryViaBroker(
		_In_     LPCTSTR               lpPathName,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes
	);

	HANDLE CreateFileViaBroker(
		_In_     LPCTSTR               lpFileName,
		_In_     DWORD                 dwDesiredAccess,
		_In_     DWORD                 dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_     DWORD                 dwCreationDisposition,
		_In_     DWORD                 dwFlagsAndAttributes,
		_In_opt_ HANDLE                hTemplateFile
	);

	DWORD HandleInputViaBroker(PWCHAR Input, DWORD InputSize);

	BOOL HandleOutputViaBroker(PWCHAR Message);
};
