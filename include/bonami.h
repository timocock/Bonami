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
#include <netinet/in.h>

/* Version information */
#define BONAMI_VERSION    1
#define BONAMI_REVISION   0

/* Protocol-specific error codes */
#define BONAMI_OK              0   /* Operation successful */
#define BONAMI_BADPARAM       -1  /* Invalid parameter */
#define BONAMI_NOMEM          -2  /* Out of memory */
#define BONAMI_TIMEOUT        -3  /* Operation timed out */
#define BONAMI_DUPLICATE      -4  /* Service already registered */
#define BONAMI_NOTFOUND       -5  /* Service not found */
#define BONAMI_BADTYPE        -6  /* Invalid service type */
#define BONAMI_BADNAME        -7  /* Invalid service name */
#define BONAMI_BADPORT        -8  /* Invalid port number */
#define BONAMI_BADTXT         -9  /* Invalid TXT record */
#define BONAMI_BADQUERY       -10 /* Invalid DNS query */
#define BONAMI_BADRESPONSE    -11 /* Invalid DNS response */
#define BONAMI_NETWORK        -12 /* Network error */
#define BONAMI_NOTREADY       -13 /* Network not ready */
#define BONAMI_BUSY           -14 /* Operation in progress */
#define BONAMI_CANCELLED      -15 /* Operation cancelled */

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
#define BONAMI_SERVICE_SSH     "_ssh._tcp"
#define BONAMI_SERVICE_PRINT   "_printer._tcp"

/* Structure for service registration */
struct BonamiService {
    char name[BONAMI_MAX_NAME_LEN];
    char type[BONAMI_MAX_SERVICE_LEN];
    char hostname[BONAMI_MAX_NAME_LEN];
    struct in_addr addr;
    UWORD port;
    struct BonamiTXTRecord *txt;
};

/* Structure for service discovery */
struct BonamiDiscovery {
    char type[BONAMI_MAX_SERVICE_LEN];
    struct List *services; /* List of BonamiServiceInfo */
    struct SignalSemaphore *lock;
    void (*callback)(struct BonamiServiceInfo *info, int event); /* Async callback */
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

/* Event types for callbacks */
#define BONAMI_EVENT_ADDED    1
#define BONAMI_EVENT_REMOVED  2
#define BONAMI_EVENT_UPDATED  3

/* Library base structure (internal use) */
struct BonamiBase {
    struct Library lib;
    struct SignalSemaphore lock;
    struct MsgPort *replyPort;
    struct Task *mainTask;
    ULONG flags;
};

/* TXT record structure */
struct BonamiTXTRecord {
    char key[BONAMI_MAX_TXT_LEN];
    char value[BONAMI_MAX_TXT_LEN];
    struct BonamiTXTRecord *next;
};

/* Discovery structure */
struct BonamiDiscovery {
    char type[BONAMI_MAX_SERVICE_LEN];
    void (*callback)(struct BonamiService *service, APTR userData);
    APTR userData;
};

/* Filter structure */
struct BonamiFilter {
    char txtKey[BONAMI_MAX_TXT_LEN];
    char txtValue[BONAMI_MAX_TXT_LEN];
    BOOL wildcard;
};

/* Monitor structure */
struct BonamiMonitor {
    struct Node node;
    char name[BONAMI_MAX_NAME_LEN];
    char type[BONAMI_MAX_SERVICE_LEN];
    LONG checkInterval;
    BOOL notifyOffline;
    BOOL running;
    void (*callback)(struct BonamiService *service, APTR userData);
    APTR userData;
};

/* Batch structure */
struct BonamiBatch {
    struct BonamiService *services;
    ULONG numServices;
    ULONG maxServices;
};

/* Interface structure */
struct BonamiInterface {
    char name[BONAMI_MAX_NAME_LEN];
    struct in_addr addr;
    struct in_addr netmask;
    BOOL up;
    BOOL preferred;
};

/* Configuration structure */
struct BonamiConfig {
    LONG discoveryTimeout;
    LONG resolveTimeout;
    LONG ttl;
    BOOL autoReconnect;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Public API */
LONG BonamiRegisterService(struct BonamiService *service);
LONG BonamiUnregisterService(const char *name, const char *type);
LONG BonamiStartDiscovery(struct BonamiDiscovery *discovery);
LONG BonamiStopDiscovery(struct BonamiDiscovery *discovery);
LONG BonamiGetServiceInfo(struct BonamiServiceInfo *info, const char *name, const char *type);
LONG BonamiEnumerateServices(struct List *services, const char *type);

/* New: Enumerate all service types currently advertised */
LONG BonamiEnumerateServiceTypes(struct List *types);

/* New: Query arbitrary DNS record (advanced) */
LONG BonamiQueryRecord(const char *name, UWORD type, UWORD class, void *result, LONG resultlen);

/* New: Set async callback for discovery events */
LONG BonamiSetDiscoveryCallback(struct BonamiDiscovery *discovery, void (*callback)(struct BonamiServiceInfo *info, int event));

/* New: Update TXT record for a registered service */
LONG BonamiUpdateServiceTXT(const char *name, const char *type, const char *txt);

/* New: Update/rename a registered service */
LONG BonamiUpdateService(struct BonamiService *service);

/* New: Resolve a service */
LONG BonamiResolveService(const char *name, const char *type, struct BonamiService *service);

/* New: Start filtered discovery */
LONG BonamiStartFilteredDiscovery(const char *type, struct BonamiFilter *filter, void (*callback)(struct BonamiService *service, APTR userData), APTR userData);

/* New: Monitor a service */
LONG BonamiMonitorService(const char *name, const char *type, LONG checkInterval, BOOL notifyOffline);

/* New: Get services */
LONG BonamiGetServices(const char *type, struct BonamiService *services, ULONG *numServices);

/* New: Set configuration */
LONG BonamiSetConfig(struct BonamiConfig *config);

/* New: Get configuration */
LONG BonamiGetConfig(struct BonamiConfig *config);

/* New: Get interfaces */
LONG BonamiGetInterfaces(struct BonamiInterface *interfaces, ULONG *numInterfaces);

/* New: Set preferred interface */
LONG BonamiSetPreferredInterface(const char *interface);

/* New: Register update callback */
LONG BonamiRegisterUpdateCallback(const char *name, const char *type, void (*callback)(struct BonamiService *service, APTR userData), APTR userData);

/* New: Unregister update callback */
LONG BonamiUnregisterUpdateCallback(const char *name, const char *type);

/* TXT record functions */
struct BonamiTXTRecord *BonamiCreateTXTRecord(const char *key, const char *value);
void BonamiFreeTXTRecord(struct BonamiTXTRecord *record);

#ifdef __cplusplus
}
#endif

#endif /* BONAMI_H */ 