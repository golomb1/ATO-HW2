#include "stdafx.h"
#include "ErrorMessage.h"

wchar_t error_meessage[ERROR_SIZE];

void SetError(
	__in LPCWSTR Message,
	__in DWORD   ErrorCode)
{
	if (wcslen(Message) < ERROR_SIZE - wcslen(FORMAT) - 1) {
		swprintf_s(error_meessage, FORMAT, Message, ErrorCode);
	}
}