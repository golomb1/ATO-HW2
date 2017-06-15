// RequestHandler.cpp : Defines the exported functions for the DLL application.
//

#include  "stdafx.h"
#include  "RequestHandler.h"	

RequestHandler::RequestHandler(__in_opt PVOID data, __in HANDLE read, __in HANDLE write)
{
	IPC = new PipeIPC(data, read, write);
}


RequestHandler::~RequestHandler()
{
	delete IPC;
}


///********************************************************///
///					Server Operation 
///********************************************************///


BOOL RequestHandler::HandleMessage()
{
	return IPC->HandleMessage();
}


VOID RequestHandler::SetHandler(__in int index, __in RequestHandle handler) {
	IPC->SetHandler(index, handler);
}


///********************************************************///
///					Client Operation 
///********************************************************///

BOOL RequestHandler::NotifyOnInitilizationComplete() {
	/// Create a buffer to send through the pipe.
	/// But first, calcualte the needed size;
	DWORD totalSize = sizeof(WCHAR);
	/// We will send an dummpy message since the
	/// scheme needs to have a non empty body.
	WCHAR buffer[1];
	buffer[0] = 0;
	byte result[MAX_PIPE_MESSAGE];
	if (!IPC->SendMessage(NOTIFY_PROCESS_INITLIZATION_COMPLETE, buffer, totalSize, MAX_PIPE_MESSAGE, result)) {
		return FALSE;
	}
	IPCMessageHeader* response = (IPCMessageHeader*)result;
	if (response == NULL || response->Flags == ERROR_TYPE || response->BodyLength != sizeof(BOOL)) {
		SetLastError(response->Flags);
		return FALSE;
	}
	else {
		BOOL value = *((BOOL*)(result + sizeof(IPCMessageHeader)));
		return value;
	}
}

HANDLE RequestHandler::CreateFileViaBroker(
	_In_     LPCTSTR               lpFileName,
	_In_     DWORD                 dwDesiredAccess,
	_In_     DWORD                 dwShareMode,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_In_     DWORD                 dwCreationDisposition,
	_In_     DWORD                 dwFlagsAndAttributes,
	_In_opt_ HANDLE                hTemplateFile)
{
	/// Create a buffer to send through the pipe.
	/// But first, calcualte the needed size;
	DWORD totalSize = 0;
	size_t nameLength = (wcslen(lpFileName) * sizeof(wchar_t));
	size_t security_attribute_size = 0;
	if (lpSecurityAttributes != NULL) {
		security_attribute_size = lpSecurityAttributes->nLength;
	}

	/// Prepare the request data.
	CreateFileRequest request;
	ZeroMemory(&request, sizeof(request));
	request.NameLength = nameLength;
	request.dwDesiredAccess = dwDesiredAccess;
	request.dwShareMode = dwShareMode;
	request.lpSecurityAttributesLength = security_attribute_size;
	request.dwCreationDisposition = dwCreationDisposition;
	request.dwFlagsAndAttributes = dwFlagsAndAttributes;
	request.hTemplateFile = hTemplateFile;

	DWORD size = sizeof(CreateFileRequest) + nameLength + security_attribute_size;
	if (size >= MAX_PIPE_MESSAGE) {
		SetLastError(ERROR_MRM_FILEPATH_TOO_LONG);
		return INVALID_HANDLE_VALUE;
	}
	
	PBYTE requestBody = new byte[size];
	ZeroMemory(requestBody, size);
	memcpy_s(requestBody, size, &request, sizeof(CreateFileRequest));
	wcscpy_s((wchar_t*)(requestBody + sizeof(request)), nameLength, lpFileName);
	if (lpSecurityAttributes != NULL) {
		memcpy_s(requestBody + sizeof(request) + nameLength, size - sizeof(request) - nameLength,
			lpSecurityAttributes, security_attribute_size);
	}
	byte result[MAX_PIPE_MESSAGE];
	if (!IPC->SendMessage(CREATE_FILE_REQUEST_TYPE, requestBody, size, MAX_PIPE_MESSAGE, result)) {
		return INVALID_HANDLE_VALUE;
	}

	IPCMessageHeader* response = (IPCMessageHeader*)result;
	if (response == NULL || response->Flags == ERROR_TYPE || response->BodyLength != sizeof(HANDLE)) {
		SetLastError(response->Flags);
		return INVALID_HANDLE_VALUE;
	}

	else {
		HANDLE handle = *((HANDLE*)(result + sizeof(IPCMessageHeader)));
		return handle;
	}
}


BOOL RequestHandler::CreateDirectoryViaBroker(
	_In_     LPCTSTR               lpPathName,
	_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes) 
{
	/// Create a buffer to send through the pipe.
	/// But first, calcualte the needed size;
	DWORD totalSize = 0;
	size_t pathLength = (wcslen(lpPathName)*sizeof(wchar_t));
	size_t security_attribute_size = 0;
	if (lpSecurityAttributes != NULL) {
		security_attribute_size = lpSecurityAttributes->nLength;
	}
	/// Prepare the request data.
	CreateDirectoryRequest request;
	ZeroMemory(&request, sizeof(request));
	request.NameLength = pathLength;
	request.lpSecurityAttributesLength = security_attribute_size;
	
	DWORD size = sizeof(CreateDirectoryRequest) + pathLength + security_attribute_size;
	if (size >= MAX_PIPE_MESSAGE) {
		SetLastError(ERROR_MRM_FILEPATH_TOO_LONG);
		return FALSE;
	}

	PBYTE requestBody = new byte[size];
	ZeroMemory(requestBody, size);
	memcpy_s(requestBody, size, &request, sizeof(CreateDirectoryRequest));
	wcscpy_s((PWCHAR)(requestBody + sizeof(request)), pathLength, lpPathName);
	if (lpSecurityAttributes != NULL) {
		memcpy_s(requestBody + sizeof(request) + pathLength, size - sizeof(request) - pathLength,
			lpSecurityAttributes, security_attribute_size);
	}

	byte result[MAX_PIPE_MESSAGE];
	if (!IPC->SendMessage(CREATE_FILE_REQUEST_TYPE, requestBody, size, MAX_PIPE_MESSAGE, result)) {
		delete requestBody;
		return FALSE;
	}

	IPCMessageHeader* response = (IPCMessageHeader*)result;
	if (response == NULL || response->Flags == ERROR_TYPE || response->BodyLength != sizeof(BOOL)) {
		SetLastError(response->Flags);
		return FALSE;
	}
	else {
		BOOL value = *((BOOL*)(result + sizeof(IPCMessageHeader)));
		return value;
	}
}




DWORD RequestHandler::HandleInputViaBroker(__in PWCHAR Input, __in DWORD InputSize) {
	/// Create a buffer to send through the pipe.
	DWORD totalSize = sizeof(DWORD);
	byte result[MAX_PIPE_MESSAGE];
	if (!IPC->SendMessage(HANDLE_INPUT_REQUEST, &InputSize, totalSize, MAX_PIPE_MESSAGE, result)) {
		return 0;
	}
	IPCMessageHeader* response = (IPCMessageHeader*)result;
	if (response == NULL || response->Flags == ERROR_TYPE || response->BodyLength <= 0 || response->BodyLength >= InputSize) {
		SetLastError(response->Flags);
		return 0;
	}
	else {
		DWORD size = response->BodyLength / sizeof(WCHAR);
		wcscpy_s(Input, size, (PWCHAR)(result + sizeof(IPCMessageHeader)));
		return response->BodyLength;
	}
}

BOOL RequestHandler::HandleOutputViaBroker(__in PWCHAR Message) {
	/// Create a buffer to send through the pipe.
	DWORD totalSize = wcslen(Message);
	byte result[MAX_PIPE_MESSAGE];
	if (!IPC->SendMessage(HANDLE_OUTPUT_REQUEST, Message, totalSize, MAX_PIPE_MESSAGE, result)) {
		return FALSE;
	}
	IPCMessageHeader* response = (IPCMessageHeader*)result;
	if (response == NULL || response->Flags == ERROR_TYPE || response->BodyLength < sizeof(BOOL)) {
		SetLastError(response->Flags);
		return FALSE;
	}
	else {
		BOOL value = *((BOOL*)(result + sizeof(IPCMessageHeader)));
		return value;
	}
}