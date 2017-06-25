#pragma once
#include <Windows.h>

#define ERROR_SIZE			512
#define FORMAT				L"%s - Error code: %d"
extern wchar_t error_meessage[];

void SetError(
	__in LPCWSTR Message,
	__in DWORD   ErrorCode);

