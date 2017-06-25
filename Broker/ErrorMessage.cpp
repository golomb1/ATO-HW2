#include "stdafx.h"
#include "ErrorMessage.h"
#include <stdio.h>

wchar_t error_meessage[ERROR_SIZE];

void SetError(
	__in LPCWSTR Message,
	__in DWORD   ErrorCode)
{
	if (wcslen(Message) * sizeof(WCHAR) < ERROR_SIZE - wcslen(FORMAT) * sizeof(WCHAR) - 1) {
		swprintf_s(error_meessage, FORMAT, Message, ErrorCode);
	}
}