#ifndef BONAMI_H
#define BONAMI_H

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>

/* Version information */
#define BONAMI_VERSION    1
#define BONAMI_REVISION   0

/* Error codes */
#define BONAMI_OK         0
#define BONAMI_ERROR     -1
#define BONAMI_NOMEM     -2
#define BONAMI_TIMEOUT   -3
#define BONAMI_BADPARAM  -4

/* Maximum lengths */
#define BONAMI_MAX_NAME_LEN    256
#define BONAMI_MAX_SERVICE_LEN 64
#define BONAMI_MAX_TXT_LEN     256
#define BONAMI_MAX_RECORDS     32

/* Service types */
#define BONAMI_SERVICE_HTTP    "_http._tcp"
#define BONAMI_SERVICE_FTP     "_ftp._tcp"
#define BONAMI_SERVICE_SMB     "_smb._tcp"
#define BONAMI_SERVICE_AFP     "_afp._tcp"

/* Structure for service registration */
struct BonamiService {
    char name[BONAMI_MAX_NAME_LEN];
    char type[BONAMI_MAX_SERVICE_LEN];
    UWORD port;
    char txt[BONAMI_MAX_TXT_LEN];
    ULONG ttl;
};

/* Structure for service discovery */
struct BonamiDiscovery {
    char type[BONAMI_MAX_SERVICE_LEN];
    struct List *services;
    struct SignalSemaphore *lock;
};

/* Structure for discovered service */
struct BonamiServiceInfo {
    struct Node node;
    char name[BONAMI_MAX_NAME_LEN];
    char type[BONAMI_MAX_SERVICE_LEN];
    UWORD port;
    char txt[BONAMI_MAX_TXT_LEN];
    ULONG ip;
    ULONG ttl;
};

/* Library base structure */
struct BonamiBase {
    struct Library lib;
    struct SignalSemaphore lock;
    struct MsgPort *replyPort;
    struct Task *mainTask;
    ULONG flags;
    /* Add more fields as needed */
};

/* Function prototypes */
LONG BonamiRegisterService(struct BonamiService *service);
LONG BonamiUnregisterService(const char *name, const char *type);
LONG BonamiStartDiscovery(struct BonamiDiscovery *discovery);
LONG BonamiStopDiscovery(struct BonamiDiscovery *discovery);
LONG BonamiGetServiceInfo(struct BonamiServiceInfo *info, const char *name, const char *type);
LONG BonamiEnumerateServices(struct List *services, const char *type);

#endif /* BONAMI_H */ 