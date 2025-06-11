; find_samba.sh - Find Samba shares using bactl
; Usage: find_samba.sh [TIMEOUT=n]

.KEY TIMEOUT/N

; Set default timeout if not specified
IF NOT VAL $TIMEOUT
    TIMEOUT=5
ENDIF

; Start discovery
bactl discover _smb._tcp.local

; Wait for responses
WAIT $TIMEOUT

; List found services
bactl list _smb._tcp.local

; Stop discovery
bactl stop _smb._tcp.local 