#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/roadshow.h>
#include <string.h>
#include <stdio.h>

#include "/include/bonami.h"
#include "/include/dns.h"

/* Library version */
#define LIB_VERSION    40
#define LIB_REVISION   0
#define LIB_IDSTRING   "BonAmi mDNS Library 40.0"

/* Memory pool sizes */
#define POOL_PUDDLE_SIZE   4096
#define POOL_THRESHOLD     256
#define POOL_MAX_PUDDLES   16

/* Message types for daemon communication */
#define MSG_REGISTER   1
#define MSG_UNREGISTER 2
#define MSG_DISCOVER   3
#define MSG_STOP       4
#define MSG_UPDATE     5
#define MSG_RESOLVE    6
#define MSG_MONITOR    7
#define MSG_CONFIG     8
#define MSG_ENUMERATE  9

/* Message structure for daemon communication */
struct BAMessage {
    struct Message msg;
    ULONG type;
    union {
        struct {
            struct BAService *service;
            LONG result;
        } register_msg;
        struct {
            char name[BA_MAX_NAME_LEN];
            char type[BA_MAX_SERVICE_LEN];
            LONG result;
        } unregister_msg;
        struct {
            char type[BA_MAX_SERVICE_LEN];
            struct List *services;
            LONG result;
        } discover_msg;
        struct {
            char name[BA_MAX_NAME_LEN];
            char type[BA_MAX_SERVICE_LEN];
            struct BAService *service;
            LONG result;
        } resolve_msg;
        struct {
            char name[BA_MAX_NAME_LEN];
            char type[BA_MAX_SERVICE_LEN];
            struct BAMonitor *monitor;
            LONG interval;
            BOOL notify;
            LONG result;
        } monitor_msg;
        struct {
            struct BAConfig *config;
            LONG result;
        } config_msg;
        struct {
            char name[BA_MAX_NAME_LEN];
            char type[BA_MAX_SERVICE_LEN];
            struct BATXTRecord *txt;
            LONG result;
        } update_msg;
        struct {
            struct List *types;
            LONG result;
        } enumerate_msg;
    } data;
};

/* Library base structure */
struct BABase {
    struct Library lib;
    struct SignalSemaphore lock;
    struct SignalSemaphore msgLock;  /* For message handling */
    struct MsgPort *replyPort;
    struct Task *mainTask;
    struct List monitors;
    struct List updateCallbacks;
    struct BAConfig config;
    ULONG flags;
    ULONG openCount;  /* Library open count */
    APTR memPool;     /* Memory pool for allocations */
    #ifdef __amigaos4__
    struct ExecIFace *IExec;
    struct DOSIFace *IDOS;
    struct RoadshowIFace *IRoadshow;
    #endif
};

/* Function prototypes */
static LONG sendMessage(struct BABase *base, struct BAMessage *msg);
static LONG waitForReply(struct BABase *base, struct BAMessage *msg);
static void monitorTask(void *arg);
static BOOL matchFilter(struct BAService *service, struct BAFilter *filter);
static LONG validateServiceType(const char *type);

/**
 * OpenLibrary - Initialize and open the BonAmi library
 * 
 * This function initializes the BonAmi library, creating necessary structures
 * and setting up communication with the BonAmi daemon. It allocates memory
 * for the library base, initializes semaphores and lists, and creates a
 * reply port for message communication.
 * 
 * @return Pointer to the library base structure, or NULL if initialization fails
 */
struct Library *OpenLibrary(void)
{
    struct BABase *base;
    struct Library *lib;
    
    /* Check if library is already open */
    lib = FindLibrary("bonami.library");
    if (lib) {
        base = (struct BABase *)lib;
        ObtainSemaphore(&base->lock);
        base->openCount++;
        ReleaseSemaphore(&base->lock);
        return lib;
    }
    
    /* Allocate library base */
    base = (struct BABase *)AllocVec(sizeof(struct BABase), MEMF_CLEAR | MEMF_PUBLIC);
    if (!base) {
        return NULL;
    }
    
    /* Initialize library */
    base->lib.lib_Node.ln_Type = NT_LIBRARY;
    base->lib.lib_Node.ln_Name = "bonami.library";
    base->lib.lib_Flags = LIBF_SUMUSED | LIBF_CHANGED;
    base->lib.lib_Version = LIB_VERSION;
    base->lib.lib_Revision = LIB_REVISION;
    base->lib.lib_IdString = LIB_IDSTRING;
    
    /* Initialize semaphores */
    InitSemaphore(&base->lock);
    InitSemaphore(&base->msgLock);
    
    /* Initialize lists */
    NewList(&base->monitors);
    NewList(&base->updateCallbacks);
    
    /* Create memory pool */
    base->memPool = CreatePool(MEMF_ANY, POOL_PUDDLE_SIZE, POOL_THRESHOLD);
    if (!base->memPool) {
        FreeVec(base);
        return NULL;
    }
    
    /* Initialize config */
    memset(&base->config, 0, sizeof(struct BAConfig));
    base->config.discoveryTimeout = 5;
    base->config.resolveTimeout = 2;
    base->config.ttl = 120;
    base->config.autoReconnect = TRUE;
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    /* Find daemon port */
    base->mainTask = FindTask(NULL);
    if (!base->mainTask) {
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    #ifdef __amigaos4__
    /* Get interfaces */
    struct Library *execBase = OpenLibrary("exec.library", 40);
    if (!execBase) {
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    base->IExec = (struct ExecIFace *)GetInterface(execBase, "main", 1, NULL);
    if (!base->IExec) {
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    struct Library *dosBase = OpenLibrary("dos.library", 40);
    if (!dosBase) {
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    base->IDOS = (struct DOSIFace *)GetInterface(dosBase, "main", 1, NULL);
    if (!base->IDOS) {
        CloseLibrary(dosBase);
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    struct Library *roadshowBase = OpenLibrary("roadshow.library", 40);
    if (!roadshowBase) {
        DropInterface((struct Interface *)base->IDOS);
        CloseLibrary(dosBase);
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    
    base->IRoadshow = (struct RoadshowIFace *)GetInterface(roadshowBase, "main", 1, NULL);
    if (!base->IRoadshow) {
        CloseLibrary(roadshowBase);
        DropInterface((struct Interface *)base->IDOS);
        CloseLibrary(dosBase);
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        DeletePool(base->memPool);
        FreeVec(base);
        return NULL;
    }
    #endif
    
    /* Set initial open count */
    base->openCount = 1;
    
    /* Add to system */
    AddLibrary((struct Library *)base);
    
    return (struct Library *)base;
}

/**
 * CloseLibrary - Clean up and close the BonAmi library
 * 
 * This function performs cleanup operations when the library is closed.
 * It frees all allocated memory, removes monitors and callbacks,
 * and deletes the reply port.
 */
void CloseLibrary(void)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    
    if (!base) return;
    
    /* Decrement open count */
    ObtainSemaphore(&base->lock);
    if (--base->openCount > 0) {
        ReleaseSemaphore(&base->lock);
        return;
    }
    ReleaseSemaphore(&base->lock);
    
    /* Remove from system */
    RemLibrary((struct Library *)base);
    
    /* Free monitors */
    ObtainSemaphore(&base->lock);
    while (!IsListEmpty(&base->monitors)) {
        struct BAMonitor *monitor = (struct BAMonitor *)RemHead(&base->monitors);
        FreePooled(base, monitor, sizeof(struct BAMonitor));
    }
    ReleaseSemaphore(&base->lock);
    
    /* Free update callbacks */
    ObtainSemaphore(&base->lock);
    while (!IsListEmpty(&base->updateCallbacks)) {
        struct BAUpdateCallback *cb = (struct BAUpdateCallback *)RemHead(&base->updateCallbacks);
        FreePooled(base, cb, sizeof(struct BAUpdateCallback));
    }
    ReleaseSemaphore(&base->lock);
    
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
    }
    
    #ifdef __amigaos4__
    /* Drop interfaces */
    if (base->IRoadshow) {
        struct Library *roadshowBase = base->IRoadshow->Data.LibBase;
        DropInterface((struct Interface *)base->IRoadshow);
        CloseLibrary(roadshowBase);
        base->IRoadshow = NULL;
    }
    
    if (base->IDOS) {
        struct Library *dosBase = base->IDOS->Data.LibBase;
        DropInterface((struct Interface *)base->IDOS);
        CloseLibrary(dosBase);
        base->IDOS = NULL;
    }
    
    if (base->IExec) {
        struct Library *execBase = base->IExec->Data.LibBase;
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        base->IExec = NULL;
    }
    #endif
    
    /* Delete memory pool */
    DeletePool(base->memPool);
    
    FreeVec(base);
}

/**
 * ExpungeLibrary - Remove the library from memory
 * 
 * This function is called when the library is to be removed from memory.
 * Currently, no special cleanup is required as CloseLibrary handles everything.
 */
void ExpungeLibrary(void)
{
    /* Nothing to do here */
}

/**
 * BARegisterService - Register a service for advertisement
 * 
 * Registers a service for advertisement on the local network using mDNS.
 * The service will be probed for conflicts before being announced.
 * 
 * @param service Pointer to a BAService structure containing service details
 * @return BA_OK if successful, error code otherwise
 * @see BAService
 */
LONG BARegisterService(struct BAService *service)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    LONG result;
    
    if (!service || !service->name[0] || !service->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Validate service type */
    result = validateServiceType(service->type);
    if (result != BA_OK) {
        return result;
    }
    
    /* Obtain semaphore */
    ObtainSemaphore(&base->lock);
    
    /* Allocate message from pool */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        ReleaseSemaphore(&base->lock);
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_REGISTER;
    memcpy(&msg->data.register_msg.service, service, sizeof(struct BAService));
    msg->data.register_msg.result = BA_OK;
    
    /* Send to daemon */
    result = sendMessage(base, msg);
    if (result == BA_OK) {
        result = waitForReply(base, msg);
        if (result == BA_OK) {
            result = msg->data.register_msg.result;
        }
    }
    
    FreePooled(base, msg, sizeof(struct BAMessage));
    
    /* Release semaphore */
    ReleaseSemaphore(&base->lock);
    
    return result;
}

/**
 * BAUnregisterService - Unregister a previously registered service
 * 
 * Removes a service from advertisement and cleans up associated resources.
 * 
 * @param name Service instance name
 * @param type Service type (e.g., "_http._tcp.local")
 * @return BA_OK if successful, error code otherwise
 */
LONG BAUnregisterService(const char *name, const char *type)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!name || !type) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_UNREGISTER;
    strncpy(msg->data.unregister_msg.name, name, sizeof(msg->data.unregister_msg.name) - 1);
    strncpy(msg->data.unregister_msg.type, type, sizeof(msg->data.unregister_msg.type) - 1);
    msg->data.unregister_msg.result = BA_OK;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        result = waitForReply(base, msg);
        if (result == BA_OK) {
            result = msg->data.unregister_msg.result;
        }
    }
    
    FreePooled(base, msg, sizeof(struct BAMessage));
    
    return result;
}

/**
 * BAStartDiscovery - Start discovering services of a specific type
 * 
 * Initiates service discovery for the specified service type. Results
 * will be added to the provided list structure.
 * 
 * @param discovery Pointer to a BADiscovery structure
 * @return BA_OK if successful, error code otherwise
 * @see BADiscovery
 */
LONG BAStartDiscovery(struct BADiscovery *discovery)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, discovery->type, sizeof(msg->data.discover_msg.type) - 1);
    msg->data.discover_msg.services = discovery->services;
    msg->data.discover_msg.result = BA_OK;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        result = waitForReply(base, msg);
        if (result == BA_OK) {
            result = msg->data.discover_msg.result;
        }
    }
    
    FreePooled(base, msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BAStopDiscovery - Stop an active service discovery
 * 
 * Stops an ongoing service discovery operation and cleans up resources.
 * 
 * @param discovery Pointer to the BADiscovery structure used in BAStartDiscovery
 * @return BA_OK if successful, error code otherwise
 */
LONG BAStopDiscovery(struct BADiscovery *discovery)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_STOP;
    strncpy(msg->data.discover_msg.type, discovery->type, sizeof(msg->data.discover_msg.type) - 1);
    msg->data.discover_msg.result = BA_OK;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        result = waitForReply(base, msg);
        if (result == BA_OK) {
            result = msg->data.discover_msg.result;
        }
    }
    
    FreePooled(base, msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BAMonitorService - Monitor a service for availability changes
 * 
 * Sets up monitoring for a specific service instance. The callback will be
 * called when the service state changes.
 * 
 * @param name Service instance name
 * @param type Service type
 * @param checkInterval Interval between checks in seconds
 * @param notifyOffline Whether to notify when service goes offline
 * @return BA_OK if successful, error code otherwise
 */
LONG BAMonitorService(const char *name,
                         const char *type,
                         LONG checkInterval,
                         BOOL notifyOffline)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    struct BAMonitor *monitor;
    
    if (!name || !type) {
        return BA_BADPARAM;
    }
    
    /* Create monitor structure */
    monitor = AllocPooled(base, sizeof(struct BAMonitor));
    if (!monitor) {
        return BA_NOMEM;
    }
    
    /* Initialize monitor */
    strncpy(monitor->name, name, sizeof(monitor->name) - 1);
    strncpy(monitor->type, type, sizeof(monitor->type) - 1);
    monitor->checkInterval = checkInterval;
    monitor->notifyOffline = notifyOffline;
    
    /* Allocate message */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        FreePooled(base, monitor, sizeof(struct BAMonitor));
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_MONITOR;
    memcpy(&msg->data.monitor_msg.monitor, monitor, sizeof(struct BAMonitor));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        /* Add to monitor list */
        AddTail(base->monitors, (struct Node *)monitor);
    } else {
        FreePooled(base, monitor, sizeof(struct BAMonitor));
    }
    
    FreePooled(base, msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BAGetServices - Get a list of services of a specific type
 * 
 * Retrieves all currently known services of the specified type.
 * 
 * @param type Service type to query
 * @param services Array to store found services
 * @param numServices Pointer to store number of services found
 * @return BA_OK if successful, error code otherwise
 */
LONG BAGetServices(const char *type,
                      struct BAService *services,
                      ULONG *numServices)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    struct BABatch batch;
    
    if (!type || !services || !numServices) {
        return BA_BADPARAM;
    }
    
    /* Set up batch */
    batch.services = services;
    batch.numServices = 0;
    batch.maxServices = *numServices;
    
    /* Allocate message */
    msg = AllocPooled(base, sizeof(struct BAMessage));
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, type, sizeof(msg->data.discover_msg.type) - 1);
    msg->data.discover_msg.services = &batch.services;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        *numServices = batch.numServices;
    }
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BASetConfig - Set library configuration
 * 
 * Updates the library's configuration settings.
 * 
 * @param config Pointer to BAConfig structure with new settings
 * @return BA_OK if successful, error code otherwise
 * @see BAConfig
 */
LONG BASetConfig(struct BAConfig *config)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!config) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_CONFIG;
    memcpy(&msg->data.config_msg.config, config, sizeof(struct BAConfig));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        /* Update local config */
        memcpy(&base->config, config, sizeof(struct BAConfig));
    }
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BAGetConfig - Get current library configuration
 * 
 * Retrieves the current library configuration settings.
 * 
 * @param config Pointer to BAConfig structure to store settings
 * @return BA_OK if successful, error code otherwise
 */
LONG BAGetConfig(struct BAConfig *config)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    
    if (!config) {
        return BA_BADPARAM;
    }
    
    /* Copy current config */
    memcpy(config, &base->config, sizeof(struct BAConfig));
    return BA_OK;
}

/* Send message to daemon */
static LONG sendMessage(struct BABase *base, struct BAMessage *msg)
{
    if (!base || !msg) return BA_BADPARAM;
    
    ObtainSemaphore(&base->msgLock);
    
    if (!base->mainTask || !base->replyPort) {
        ReleaseSemaphore(&base->msgLock);
        return BA_NOTREADY;
    }
    
    msg->msg.mn_ReplyPort = base->replyPort;
    msg->msg.mn_Length = sizeof(struct BAMessage);
    
    PutMsg(base->mainTask, (struct Message *)msg);
    
    ReleaseSemaphore(&base->msgLock);
    return BA_OK;
}

/* Wait for reply from daemon */
static LONG waitForReply(struct BABase *base, struct BAMessage *msg)
{
    if (!base || !msg) return BA_BADPARAM;
    
    ObtainSemaphore(&base->msgLock);
    
    if (!base->replyPort) {
        ReleaseSemaphore(&base->msgLock);
        return BA_NOTREADY;
    }
    
    WaitPort(base->replyPort);
    GetMsg(base->replyPort);
    
    ReleaseSemaphore(&base->msgLock);
    return BA_OK;
}

/* Match service against filter */
static BOOL matchFilter(struct BAService *service, struct BAFilter *filter)
{
    if (!filter->txtKey) {
        return TRUE;  // No filter
    }
    
    /* Check TXT records */
    struct BATXTRecord *txt = service->txt;
    while (txt) {
        if (strcmp(txt->key, filter->txtKey) == 0) {
            if (filter->wildcard) {
                return strstr(txt->value, filter->txtValue) != NULL;
            } else {
                return strcmp(txt->value, filter->txtValue) == 0;
            }
        }
        txt = txt->next;
    }
    
    return FALSE;
}

/* Monitor task */
static void monitorTask(void *arg)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMonitor *monitor = (struct BAMonitor *)arg;
    struct BAService service;
    LONG result;
    
    while (monitor->running) {
        /* Check service */
        result = BAGetServiceInfo(&service, monitor->name, monitor->type);
        
        if (result != BA_OK && monitor->notifyOffline) {
            /* Service is offline, notify */
            if (monitor->callback) {
                monitor->callback(NULL, monitor->userData);
            }
        }
        
        /* Wait for next check */
        Delay(monitor->checkInterval * 50);  // Convert to ticks
    }
}

/**
 * BAGetServiceInfo - Get detailed information about a service
 * 
 * Resolves a specific service instance to get its complete information.
 * 
 * @param info Pointer to BAServiceInfo structure to store service details
 * @param name Service instance name
 * @param type Service type
 * @return BA_OK if successful, error code otherwise
 */
LONG BAGetServiceInfo(struct BAServiceInfo *info, const char *name, const char *type)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    struct hostent *host;
    
    if (!name || !type || !info) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_RESOLVE;
    strncpy(msg->data.resolve_msg.name, name, sizeof(msg->data.resolve_msg.name) - 1);
    strncpy(msg->data.resolve_msg.type, type, sizeof(msg->data.resolve_msg.type) - 1);
    msg->data.resolve_msg.service = (struct BAService *)info;
    msg->data.resolve_msg.result = BA_OK;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        /* Resolve hostname to IP address */
        host = gethostbyname(info->hostname);
        if (host) {
            memcpy(&info->addr, host->h_addr, sizeof(struct in_addr));
        } else {
            result = BA_RESOLVE;
        }
    }
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BACreateTXTRecord - Create a new TXT record
 * 
 * Creates a new TXT record for service metadata.
 * 
 * @param key Record key
 * @param value Record value
 * @return Pointer to new BATXTRecord, or NULL if creation fails
 */
struct BATXTRecord *BACreateTXTRecord(const char *key,
                                            const char *value)
{
    struct BATXTRecord *record;
    
    if (!key || !value) {
        return NULL;
    }
    
    /* Allocate record */
    record = AllocMem(sizeof(struct BATXTRecord), MEMF_CLEAR);
    if (!record) {
        return NULL;
    }
    
    /* Copy key and value */
    strncpy(record->key, key, sizeof(record->key) - 1);
    strncpy(record->value, value, sizeof(record->value) - 1);
    
    return record;
}

/**
 * BAFreeTXTRecord - Free a TXT record
 * 
 * Frees memory allocated for a TXT record.
 * 
 * @param record Pointer to BATXTRecord to free
 */
void BAFreeTXTRecord(struct BATXTRecord *record)
{
    if (record) {
        FreeMem(record, sizeof(struct BATXTRecord));
    }
}

/**
 * BAGetInterfaces - Get list of available network interfaces
 * 
 * Retrieves information about all available network interfaces.
 * 
 * @param interfaces Array to store interface information
 * @param numInterfaces Pointer to store number of interfaces found
 * @return BA_OK if successful, error code otherwise
 */
LONG BAGetInterfaces(struct BAInterface *interfaces,
                        ULONG *numInterfaces)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!interfaces || !numInterfaces) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    msg->data.discover_msg.type = (char *)interfaces;
    msg->data.discover_msg.services = (struct List *)interfaces;
    msg->data.discover_msg.result = BA_OK;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BA_OK) {
        *numInterfaces = ((struct List *)interfaces)->ln_NumEntries;
    }
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/**
 * BASetPreferredInterface - Set the preferred network interface
 * 
 * Sets the network interface to use for service advertisement and discovery.
 * 
 * @param interface Name of the interface to use
 * @return BA_OK if successful, error code otherwise
 */
LONG BASetPreferredInterface(const char *interface)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!interface) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, interface, sizeof(msg->data.discover_msg.type) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BAMessage));
    
    return result;
}

/**
 * BAUpdateService - Update service information
 * 
 * Updates the TXT records for a registered service.
 * 
 * @param name Service instance name
 * @param type Service type
 * @param txt New TXT records
 * @return BA_OK if successful, error code otherwise
 */
LONG BAUpdateService(const char *name,
                        const char *type,
                        struct BATXTRecord *txt)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!name || !type || !txt) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_UPDATE;
    strncpy(msg->data.update_msg.name, name, sizeof(msg->data.update_msg.name) - 1);
    strncpy(msg->data.update_msg.type, type, sizeof(msg->data.update_msg.type) - 1);
    memcpy(&msg->data.update_msg.txt, txt, sizeof(struct BATXTRecord));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BAMessage));
    
    return result;
}

/**
 * BARegisterUpdateCallback - Register callback for service updates
 * 
 * Registers a callback function to be called when a service's information changes.
 * 
 * @param name Service instance name
 * @param type Service type
 * @param cb Callback function
 * @param userData User data passed to callback
 * @return BA_OK if successful, error code otherwise
 */
LONG BARegisterUpdateCallback(const char *name,
                                const char *type,
                                BAServiceCallback cb,
                                APTR userData)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!name || !type || !cb) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, name, sizeof(msg->data.discover_msg.type) - 1);
    msg->data.discover_msg.services = (struct List *)cb;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BAMessage));
    
    return result;
}

/**
 * BAUnregisterUpdateCallback - Remove service update callback
 * 
 * Removes a previously registered service update callback.
 * 
 * @param name Service instance name
 * @param type Service type
 * @return BA_OK if successful, error code otherwise
 */
LONG BAUnregisterUpdateCallback(const char *name,
                                  const char *type)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!name || !type) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Set up message */
    msg->type = MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, name, sizeof(msg->data.discover_msg.type) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BAMessage));
    
    return result;
}

/* Validate service type */
static LONG validateServiceType(const char *type)
{
    const char *p;
    BOOL hasService = FALSE;
    BOOL hasProtocol = FALSE;
    BOOL hasLocal = FALSE;
    
    if (!type || !type[0]) {
        return BA_BADTYPE;
    }
    
    /* Check for leading underscore */
    if (type[0] != '_') {
        return BA_BADTYPE;
    }
    
    /* Parse service type */
    p = type + 1;  /* Skip leading underscore */
    
    /* Service name */
    while (*p && *p != '_') {
        if (!isalnum(*p) && *p != '-') {
            return BA_BADTYPE;
        }
        hasService = TRUE;
        p++;
    }
    
    if (!hasService) {
        return BA_BADTYPE;
    }
    
    /* Check for protocol separator */
    if (*p != '_') {
        return BA_BADTYPE;
    }
    p++;
    
    /* Protocol */
    if (strncmp(p, "tcp", 3) != 0 && strncmp(p, "udp", 3) != 0) {
        return BA_BADTYPE;
    }
    hasProtocol = TRUE;
    p += 3;
    
    /* Check for .local suffix */
    if (strcmp(p, ".local") != 0) {
        return BA_BADTYPE;
    }
    hasLocal = TRUE;
    
    return BA_OK;
}

/**
 * BAEnumerateServiceTypes - Get list of all advertised service types
 * 
 * Retrieves a list of all service types currently being advertised on the network.
 * 
 * @param types List to store found service types
 * @return BA_OK if successful, error code otherwise
 */
LONG BAEnumerateServiceTypes(struct List *types)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage msg;
    LONG result;
    
    /* Initialize message */
    memset(&msg, 0, sizeof(msg));
    msg.type = MSG_ENUMERATE;
    
    /* Send message */
    result = sendMessage(base, &msg);
    if (result != BA_OK) {
        return result;
    }
    
    /* Wait for reply */
    result = waitForReply(base, &msg);
    if (result != BA_OK) {
        return result;
    }
    
    /* Check result */
    if (msg.data.enumerate_msg.result != BA_OK) {
        return msg.data.enumerate_msg.result;
    }
    
    /* Copy types to list */
    NewList(types);
    for (const char **type = msg.data.enumerate_msg.types; *type; type++) {
        struct Node *node = AllocMem(sizeof(struct Node), MEMF_CLEAR);
        if (!node) {
            return BA_NOMEM;
        }
        
        node->ln_Name = (char *)*type;
        AddTail(types, node);
    }
    
    return BA_OK;
} 