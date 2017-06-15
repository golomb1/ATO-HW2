#pragma once
#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <Sddl.h>
#include <aclapi.h>
#include <stdlib.h>

#define DllExport   __declspec( dllexport )  
#define MAX_PIPE_MESSAGE		2048
#define ERROR_TYPE		~0
#define RESPONSE_TYPE	~1
#define	MAX_HANDLERS					200


///<summery>
/// This structure define the IPCMessageHeader.
///</summery>
struct IPCMessageHeader {
	unsigned char RequestType;
	DWORD Flags;
	DWORD BodyLength;
};

typedef PVOID(*RequestHandle)(__in PVOID ChildPid, __in PBYTE request, __in DWORD lentgh, __out PDWORD size);


class DllExport PipeIPC
{
private:
	HANDLE			readHandle;
	HANDLE			writeHandle;
	PVOID			Data;
	RequestHandle	handlers[MAX_HANDLERS];

public:

	///<summery>Constractor to initilize the class fields</summery>
	///<param name='data'>
	/// This variable is passed to the requests handles, 
	/// only if you don't plan to use it in all of your handles, you can assing null.
	///</param>
	///<param name='read'>Handle for reading information from the child.</param>
	///<param name='write'>Handle for writing information to the child.</param>
	PipeIPC(__in_opt PVOID data, __in HANDLE read, __in HANDLE write);
	
	///<summery>destrctor</summery>
	~PipeIPC();

	///<summery>
	/// This method wait for a message from the child and than handle it 
	/// using the registered request handle.
	///</summery>
	///<return>True if a request was handled successfully or False otherwise</return>
	BOOL HandleMessage();

	///<summery> allows to add a request handle for request of type @index</summery>
	///<param name='requestType'>the id of the request to handle</param>
	///<param name='handler'>the handle</param>
	VOID PipeIPC::SetHandler(__in int requestType, __in RequestHandle handler);
	
	///<summery>
	/// Use the relevant request handle for the given request.
	/// if there is not a reuqest handler for the request the function 
	/// will return NULL and set the error using SetLastError.
	///</summery>
	///<param name='header'>the request headers</param>
	///<param name='buffer'>the request body</param>
	///<param name='size'>the size of the returned buffer</param>
	///<return>
	/// Pointer to a buffer and set the returned buffer size in the param size,
	/// or NULL in case of an error.
	///</return>
	PVOID PipeIPC::Handler(__in IPCMessageHeader* header, __in PBYTE buffer, __out PDWORD size);
	
	///<summery>Send a message for the parent.</summery>
	///<param name='Type'>The type of the request.</param>
	///<param name='Buffer'>The message buffer.</param>
	///<param name='Length'>The length of the buffer.</param>
	///<param name='ResponseBufferSize'>The size of the response buffer.</param>
	///<param name='ResponseBuffer'>A buffer that will contain the response.</param>
	BOOL PipeIPC::SendMessage(
		__in	DWORD Type,
		__in	PVOID Buffer,
		__in	DWORD Length,
		__in	DWORD ResponseBufferSize,
		__out	PBYTE ResponseBuffer);
};
