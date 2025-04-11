#pragma once
#include <Windows.h>
#include "base/helpers.h"

DFR(MSVCRT, memset)
#define memset MSVCRT$memset

#ifdef __cplusplus
extern "C" {
#endif

	
    DFR(MSVCRT, _stricmp);
    #define _stricmp MSVCRT$_stricmp
    DFR(MSVCRT, memcpy);
    #define memcpy MSVCRT$memcpy
    DFR(MSVCRT, memcmp);
    #define memcmp MSVCRT$memcmp
    DFR(MSVCRT, strlen);
    #define strlen MSVCRT$strlen
    DFR(KERNEL32, CreateFileA);
    #define CreateFileA KERNEL32$CreateFileA
    DFR(KERNEL32, ReadFile);
    #define ReadFile KERNEL32$ReadFile
    DFR(KERNEL32, CloseHandle);
    #define CloseHandle KERNEL32$CloseHandle
    DFR(KERNEL32, GetFileSize);
    #define GetFileSize KERNEL32$GetFileSize
    DFR(KERNEL32, GetProcessHeap);
    #define GetProcessHeap KERNEL32$GetProcessHeap
    DFR(KERNEL32, HeapAlloc);
    #define HeapAlloc KERNEL32$HeapAlloc
    DFR(KERNEL32, HeapFree);
    #define HeapFree KERNEL32$HeapFree
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError
    DFR(ADVAPI32, RegOpenKeyExA);
    #define RegOpenKeyExA ADVAPI32$RegOpenKeyExA
    DFR(ADVAPI32, RegQueryValueExA);
    #define RegQueryValueExA ADVAPI32$RegQueryValueExA
    DFR(ADVAPI32, RegCloseKey);
    #define RegCloseKey ADVAPI32$RegCloseKey
	
	BOOL is_hex_char(char c);
	BOOL is_guid(const char* s);
	BOOL is_guid_utf16(const wchar_t* s);
	void sha256(const unsigned char* data, size_t len, unsigned char* out);
	BYTE* readFileToBuffer(const char* filePath, DWORD* pFileSize);

#ifdef __cplusplus
}
#endif