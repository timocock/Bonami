# BonAmi Examples

This directory contains example programs demonstrating how to use bonami.library.

## find_samba

A simple command-line tool that searches for Samba shares on the local network using bonami.library. This example demonstrates:
- Library initialization and cleanup
- Service discovery and enumeration
- TXT record handling
- Error handling and resource management
- Command-line argument parsing

### Usage

#### C Program
```
find_samba [TIMEOUT=n]
```

#### AmigaDOS Script
```
find_samba.sh [TIMEOUT=n]
```

Where:
- `TIMEOUT` is the number of seconds to wait for responses (default: 5)

### Example Output

```
Searching for Samba shares...

Found Samba shares:
-------------------
Name: MyShare
Host: myserver.local
Port: 445
Properties:
  path = /home/user/shared
  comment = My Shared Folder
-------------------
```

### Building

#### AmigaOS 3.x
```bash
smake
```

#### AmigaOS 4.x
```bash
make
```

### Requirements

#### AmigaOS 3.x
- bonami.library in LIBS:
- AmigaOS 3.2 or later
- Samba servers advertising their shares via mDNS
- VBCC compiler (included in AmigaOS 3.2)

#### AmigaOS 4.x
- bonami.library in LIBS:
- AmigaOS 4.1 or later
- Samba servers advertising their shares via mDNS
- GCC compiler (included in AmigaOS 4.1)

### Implementation Details

The example demonstrates several key features of bonami.library:

1. Library Initialization:
```c
struct BABase *base = BAOpen();
if (!base) {
    printf("Error: Failed to initialize bonami.library\n");
    return 1;
}
```

2. Service Discovery:
```c
result = BAStartDiscovery(base, "_smb._tcp.local", NULL);
if (result != BA_OK) {
    printf("Error: Failed to start discovery: %ld\n", result);
    return 1;
}
```

3. Service Enumeration:
```c
result = BAEnumerateServices(&services, "_smb._tcp.local");
if (result != BA_OK) {
    printf("Error: Failed to enumerate services: %ld\n", result);
    return 1;
}
```

4. TXT Record Handling:
```c
if (info->txt) {
    struct BATXTRecord *txt;
    printf("Properties:\n");
    for (txt = info->txt; txt; txt = txt->next) {
        printf("  %s = %s\n", txt->key, txt->value);
    }
}
```

5. Resource Cleanup:
```c
BAStopDiscovery(base, "_smb._tcp.local");
BAClose(base);
CloseLibrary(bonamiBase);
```

### AmigaDOS Script

The `find_samba.sh` script demonstrates how to achieve the same result using the `bactl` command-line tool:

```amigados
; Start discovery
bactl discover _smb._tcp.local

; Wait for responses
WAIT $TIMEOUT

; List found services
bactl list _smb._tcp.local

; Stop discovery
bactl stop _smb._tcp.local
```

The script:
- Uses AmigaDOS command-line argument parsing
- Provides the same timeout functionality
- Uses the same service type (_smb._tcp.local)
- Demonstrates the simplicity of using bactl

### Error Handling

The example demonstrates proper error handling:
- Library initialization failures
- Discovery start/stop failures
- Service enumeration failures
- Memory allocation failures
- Command-line parsing errors

### Notes

- The program uses ReadArgs() for command-line parsing
- All resources are properly cleaned up on exit
- Error messages are written to stdout
- The program follows AmigaOS programming guidelines 