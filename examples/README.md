# BonAmi Examples

This directory contains example programs demonstrating how to use bonami.library.

## find_samba

A simple command-line tool that searches for Samba shares on the local network using bonami.library.

### Usage

```
find_samba [TIMEOUT=n]
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

To build the example:

```bash
make
```

### Requirements

- bonami.library in LIBS:
- AmigaOS 3.2 or later
- Samba servers advertising their shares via mDNS 