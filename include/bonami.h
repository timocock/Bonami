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
#define BA_OK              0   /* Operation successful */
#define BA_BADPARAM       -1  /* Invalid parameter */
#define BA_NOMEM          -2  /* Out of memory */
#define BA_TIMEOUT        -3  /* Operation timed out */
#define BA_DUPLICATE      -4  /* Service already registered */
#define BA_NOTFOUND       -5  /* Service not found */
#define BA_BADTYPE        -6  /* Invalid service type */
#define BA_BADNAME        -7  /* Invalid service name */
#define BA_BADPORT        -8  /* Invalid port number */
#define BA_BADTXT         -9  /* Invalid TXT record */
#define BA_BADQUERY       -10 /* Invalid DNS query */
#define BA_BADRESPONSE    -11 /* Invalid DNS response */
#define BA_NETWORK        -12 /* Network error */
#define BA_NOTREADY       -13 /* Network not ready */
#define BA_BUSY           -14 /* Operation in progress */
#define BA_CANCELLED      -15 /* Operation cancelled */

/* Maximum lengths */
#define BA_MAX_NAME_LEN    256
#define BA_MAX_SERVICE_LEN 64
#define BA_MAX_TXT_LEN     256
#define BA_MAX_RECORDS     32

/* Service types */
#define BA_SERVICE_HTTP    "_http._tcp"
#define BA_SERVICE_FTP     "_ftp._tcp"
#define BA_SERVICE_SMB     "_smb._tcp"
#define BA_SERVICE_AFP     "_afp._tcp"
#define BA_SERVICE_SSH     "_ssh._tcp"
#define BA_SERVICE_PRINT   "_printer._tcp"

/* Structure for service registration */
struct BAService {
    char name[BA_MAX_NAME_LEN];
    char type[BA_MAX_SERVICE_LEN];
    char hostname[BA_MAX_NAME_LEN];
    struct in_addr addr;
    UWORD port;
    struct BATXTRecord *txt;
};

/* Structure for service discovery */
struct BADiscovery {
    char type[BA_MAX_SERVICE_LEN];
    struct List *services; /* List of BAServiceInfo */
    struct SignalSemaphore *lock;
    void (*callback)(struct BAServiceInfo *info, int event); /* Async callback */
};

/* Structure for discovered service */
struct BAServiceInfo {
    struct Node node;
    char name[BA_MAX_NAME_LEN];
    char type[BA_MAX_SERVICE_LEN];
    UWORD port;
    char txt[BA_MAX_TXT_LEN];
    ULONG ip;
    ULONG ttl;
};

/* Event types for callbacks */
#define BA_EVENT_ADDED    1
#define BA_EVENT_REMOVED  2
#define BA_EVENT_UPDATED  3

/* Library base structure (internal use) */
struct BABase {
    struct Library lib;
    struct SignalSemaphore lock;
    struct MsgPort *replyPort;
    struct Task *mainTask;
    ULONG flags;
};

/* TXT record structure */
struct BATXTRecord {
    char key[BA_MAX_TXT_LEN];
    char value[BA_MAX_TXT_LEN];
    struct BATXTRecord *next;
};

/* Discovery structure */
struct BADiscovery {
    char type[BA_MAX_SERVICE_LEN];
    void (*callback)(struct BAService *service, APTR userData);
    APTR userData;
};

/* Filter structure */
struct BAFilter {
    char txtKey[BA_MAX_TXT_LEN];
    char txtValue[BA_MAX_TXT_LEN];
    BOOL wildcard;
};

/* Monitor structure */
struct BAMonitor {
    struct Node node;
    char name[BA_MAX_NAME_LEN];
    char type[BA_MAX_SERVICE_LEN];
    LONG checkInterval;
    BOOL notifyOffline;
    BOOL running;
    void (*callback)(struct BAService *service, APTR userData);
    APTR userData;
};

/* Batch structure */
struct BABatch {
    struct BAService *services;
    ULONG numServices;
    ULONG maxServices;
};

/* Interface structure */
struct BAInterface {
    char name[BA_MAX_NAME_LEN];
    struct in_addr addr;
    struct in_addr netmask;
    BOOL up;
    BOOL preferred;
};

/* Configuration structure */
struct BAConfig {
    LONG discoveryTimeout;
    LONG resolveTimeout;
    LONG ttl;
    BOOL autoReconnect;
};

#ifdef __cplusplus
extern "C" {
#endif

/* Public API */
LONG BARegisterService(struct BAService *service);
LONG BAUnregisterService(const char *name, const char *type);
LONG BAStartDiscovery(struct BADiscovery *discovery);
LONG BAStopDiscovery(struct BADiscovery *discovery);
LONG BAGetServiceInfo(struct BAServiceInfo *info, const char *name, const char *type);
LONG BAEnumerateServices(struct List *services, const char *type);

/* New: Enumerate all service types currently advertised */
LONG BAEnumerateServiceTypes(struct List *types);

/* New: Query arbitrary DNS record (advanced) */
LONG BAQueryRecord(const char *name, UWORD type, UWORD class, void *result, LONG resultlen);

/* New: Set async callback for discovery events */
LONG BASetDiscoveryCallback(struct BADiscovery *discovery, void (*callback)(struct BAServiceInfo *info, int event));

/* New: Update TXT record for a registered service */
LONG BAUpdateServiceTXT(const char *name, const char *type, const char *txt);

/* New: Update/rename a registered service */
LONG BAUpdateService(struct BAService *service);

/* New: Resolve a service */
LONG BAResolveService(const char *name, const char *type, struct BAService *service);

/* New: Start filtered discovery */
LONG BAStartFilteredDiscovery(const char *type, struct BAFilter *filter, void (*callback)(struct BAService *service, APTR userData), APTR userData);

/* New: Monitor a service */
LONG BAMonitorService(const char *name, const char *type, LONG checkInterval, BOOL notifyOffline);

/* New: Get services */
LONG BAGetServices(const char *type, struct BAService *services, ULONG *numServices);

/* New: Set configuration */
LONG BASetConfig(struct BAConfig *config);

/* New: Get configuration */
LONG BAGetConfig(struct BAConfig *config);

/* New: Get interfaces */
LONG BAGetInterfaces(struct BAInterface *interfaces, ULONG *numInterfaces);

/* New: Set preferred interface */
LONG BASetPreferredInterface(const char *interface);

/* New: Register update callback */
LONG BARegisterUpdateCallback(const char *name, const char *type, void (*callback)(struct BAService *service, APTR userData), APTR userData);

/* New: Unregister update callback */
LONG BAUnregisterUpdateCallback(const char *name, const char *type);

/* TXT record functions */
struct BATXTRecord *BACreateTXTRecord(const char *key, const char *value);
void BAFreeTXTRecord(struct BATXTRecord *record);

#ifdef __cplusplus
}
#endif

#endif /* BONAMI_H */ 