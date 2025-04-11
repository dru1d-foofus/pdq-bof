#pragma once
#include <Windows.h>
#include "base/helpers.h"

DFR(MSVCRT, memset)
#define memset MSVCRT$memset

#ifdef __cplusplus
extern "C" {
#endif

	BOOL is_hex_char(char c);
	BOOL is_guid(const char* s);
	BOOL is_guid_utf16(const wchar_t* s);
	void sha256(const unsigned char* data, size_t len, unsigned char* out);

#ifdef __cplusplus
}
#endif