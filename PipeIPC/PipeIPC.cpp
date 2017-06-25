#include "stdafx.h"
#include "PipeIPC.h"



PipeIPC::PipeIPC(__in_opt PVOID childPid, __in HANDLE read, __in HANDLE write)
{
	readHandle	 = read;
	writeHandle	 = write;
	Data		 = childPid;
	ZeroMemory(handlers, sizeof(RequestHandle) * MAX_HANDLERS);
}


PipeIPC::~PipeIPC()
{
}


BOOL  PipeIPC::SendMessage(
	__in	DWORD Type, 
	__in	PVOID Buffer, 
	__in	DWORD Length, 
	__in	DWORD ResponseBufferSize, 
	__out	PBYTE ResponseBuffer) const
{
	/// Create the header for the request
	IPCMessageHeader header;
	ZeroMemory(&header, sizeof header);
	header.BodyLength  = Length;
	header.RequestType = Type;
	if (ResponseBufferSize < sizeof(IPCMessageHeader)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	/// Create an empty response.
	IPCMessageHeader responseHeader;
	ZeroMemory(&responseHeader, sizeof responseHeader);
	responseHeader.BodyLength	= 0;
	responseHeader.Flags		= ERROR_TYPE;
	responseHeader.RequestType	= ERROR_TYPE;

	DWORD written = 0;
	DWORD readed = 0;

	if (!(Length > 0 && Length < MAX_PIPE_MESSAGE)) {
		SetLastError(ERROR_BAD_LENGTH);
		return FALSE;
	}
	if (!WriteFile(writeHandle, &header, sizeof(IPCMessageHeader), &written, nullptr) || written != sizeof(IPCMessageHeader)) {
		OutputDebugString(L"Could not write IPCHeaders to pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return FALSE;
	}
	if (!WriteFile(writeHandle, Buffer, Length, &written, nullptr) || written != Length) {
		OutputDebugString(L"Could not write buffer to pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return FALSE;
	}
	if (!ReadFile(readHandle, &responseHeader, sizeof(IPCMessageHeader), &readed, nullptr) || readed != sizeof(IPCMessageHeader)) {
		OutputDebugString(L"Could not read IPCHeaders from pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return FALSE;
	}

	readed = 0;
	memcpy_s(ResponseBuffer, ResponseBufferSize, &responseHeader, sizeof(IPCMessageHeader));
	if (responseHeader.BodyLength > 0 && responseHeader.BodyLength < ResponseBufferSize - sizeof(IPCMessageHeader)) {
		if (!ReadFile(readHandle, ResponseBuffer + sizeof(IPCMessageHeader), responseHeader.BodyLength, &readed, nullptr) || readed != responseHeader.BodyLength) {
			OutputDebugString(L"Could not read IPCHeaders from pipe.");
			SetLastError(ERROR_BAD_ENVIRONMENT);
			return FALSE;
		}
	}
	return TRUE;
}



VOID PipeIPC::SetHandler(__in int index, __in RequestHandle handler) {
	handlers[index] = handler;
}


PVOID PipeIPC::Handler(__in IPCMessageHeader* header, __in PBYTE buffer, __out PDWORD size) {
	if (handlers[header->RequestType] == nullptr) {
		SetLastError(ERROR_INVALID_OPERATION);
		return nullptr;
	}
	return handlers[header->RequestType](Data, buffer, header->BodyLength, size);
}


BOOL PipeIPC::HandleMessage() const
{
	/// Local variable
	DWORD written = 0;
	DWORD readed  = 0;
	IPCMessageHeader message;
	IPCMessageHeader response;
	ZeroMemory(&message, sizeof(IPCMessageHeader));
	
	ZeroMemory(&response, sizeof response);
	response.BodyLength = 0;
	response.Flags = ERROR_TYPE;
	response.RequestType = ERROR_TYPE;


	if (!ReadFile(readHandle, &message, sizeof(IPCMessageHeader), &readed, nullptr) || readed != sizeof(IPCMessageHeader)) {
		OutputDebugString(L"Could not read IPCHeaders from pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return NULL;
	}

	BYTE* buffer = (BYTE*)GlobalAlloc(GPTR, sizeof(IPCMessageHeader) + message.BodyLength);
	memcpy_s(buffer, sizeof(IPCMessageHeader), &message, sizeof(IPCMessageHeader));
	if (message.BodyLength > 0 && message.BodyLength < MAX_PIPE_MESSAGE) {
		if (!ReadFile(readHandle, buffer + sizeof(IPCMessageHeader), message.BodyLength, &readed, nullptr) || readed != message.BodyLength) {
			OutputDebugString(L"Could not read IPCHeaders from pipe.");
			SetLastError(ERROR_BAD_ENVIRONMENT);
			return NULL;
		}
	}

	DWORD length;
	IPCMessageHeader* messageHeaders = (IPCMessageHeader*)buffer;
	PVOID body = handlers[messageHeaders->RequestType](Data, buffer + sizeof(IPCMessageHeader), messageHeaders->BodyLength, &length);

	ZeroMemory(&response, sizeof response);
	response.BodyLength = length;
	response.RequestType = RESPONSE_TYPE;

	if (!WriteFile(writeHandle, &response, sizeof(IPCMessageHeader), &written, nullptr) || written != sizeof(IPCMessageHeader)) {
		OutputDebugString(L"Could not write IPCHeaders to pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return FALSE;
	}
	if (!WriteFile(writeHandle, body, length, &written, nullptr) || written != length) {
		OutputDebugString(L"Could not write buffer to pipe.");
		SetLastError(ERROR_BAD_ENVIRONMENT);
		return FALSE;
	}
	GlobalFree(body);
	return TRUE;
}

