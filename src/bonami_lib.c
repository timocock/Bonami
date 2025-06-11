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
#include <netinet/in.h>

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
    struct MsgPort *replyPort;
    struct MsgPort *daemonPort;
    #ifdef __amigaos4__
    struct ExecIFace *IExec;
    struct DOSIFace *IDOS;
    #endif
};

/* Function prototypes */
static LONG sendMessage(struct BABase *base, struct BAMessage *msg);
static LONG waitForReply(struct BABase *base, struct BAMessage *msg);
static void monitorTask(void *arg);
static BOOL matchFilter(struct BAService *service, struct BAFilter *filter);
static LONG validateServiceType(const char *type);
static LONG validateServiceName(const char *name);

/* Version string */
static const char version[] = "$VER: bonami.library 40.0 (01.01.2024)";

/* Library tags */
#define LIBTAG_VERSION     (TAG_USER + 1)
#define LIBTAG_DEBUG       (TAG_USER + 2)
#define LIBTAG_MEMTRACK    (TAG_USER + 3)

/* Library base structure */
struct BonAmiBase {
    struct Library lib;
    struct SignalSemaphore sem;
    struct MsgPort *replyPort;
    struct MsgPort *bonamiPort;
    BOOL debug;
    BOOL memTrack;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
};

/* Forward declarations */
static LONG checkBonAmi(void);
static void trackMemory(APTR memory, ULONG size, const char *file, LONG line);
static void untrackMemory(APTR memory, const char *file, LONG line);

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
        base->lib.lib_OpenCnt++;
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
    base->lib.lib_OpenCnt = 1;
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        FreeVec(base);
        return NULL;
    }
    
    /* Find daemon port */
    base->daemonPort = FindPort("BonAmi");
    if (!base->daemonPort) {
        DeleteMsgPort(base->replyPort);
        FreeVec(base);
        return NULL;
    }
    
    #ifdef __amigaos4__
    /* Get interfaces */
    struct Library *execBase = OpenLibrary("exec.library", 40);
    if (!execBase) {
        DeleteMsgPort(base->replyPort);
        FreeVec(base);
        return NULL;
    }
    
    base->IExec = (struct ExecIFace *)GetInterface(execBase, "main", 1, NULL);
    if (!base->IExec) {
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        FreeVec(base);
        return NULL;
    }
    
    struct Library *dosBase = OpenLibrary("dos.library", 40);
    if (!dosBase) {
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        FreeVec(base);
        return NULL;
    }
    
    base->IDOS = (struct DOSIFace *)GetInterface(dosBase, "main", 1, NULL);
    if (!base->IDOS) {
        CloseLibrary(dosBase);
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
        DeleteMsgPort(base->replyPort);
        FreeVec(base);
        return NULL;
    }
    #endif
    
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
    if (--base->lib.lib_OpenCnt > 0) {
        return;
    }
    
    /* Remove from system */
    RemLibrary((struct Library *)base);
    
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
    }
    
    #ifdef __amigaos4__
    /* Drop interfaces */
    if (base->IDOS) {
        struct Library *dosBase = base->IDOS->Data.LibBase;
        DropInterface((struct Interface *)base->IDOS);
        CloseLibrary(dosBase);
    }
    
    if (base->IExec) {
        struct Library *execBase = base->IExec->Data.LibBase;
        DropInterface((struct Interface *)base->IExec);
        CloseLibrary(execBase);
    }
    #endif
    
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

/* Check if BonAmi is running */
static LONG checkBonAmi(void)
{
    struct MsgPort *port;
    
    /* Try to find BonAmi message port */
    port = FindPort("BonAmi");
    if (!port) {
        return BA_NOT_RUNNING;
    }
    
    return BA_OK;
}

/* Register service */
LONG BARegisterService(const struct BAService *service)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!service || !service->name || !service->type || service->port <= 0) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_REGISTER;
    msg->data.register_msg.service = *service;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Unregister service */
LONG BAUnregisterService(const char *name, const char *type)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!name || !type) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_UNREGISTER;
    msg->data.unregister_msg.name = name;
    msg->data.unregister_msg.type = type;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Start discovery */
LONG BAStartDiscovery(const struct BADiscovery *discovery)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!discovery || !discovery->type || !discovery->callback) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_DISCOVER;
    msg->data.discover_msg.discovery = *discovery;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Stop discovery */
LONG BAStopDiscovery(const struct BADiscovery *discovery)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!discovery || !discovery->type) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_STOP_DISCOVER;
    msg->data.discover_msg.discovery = *discovery;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Monitor service */
LONG BAMonitorService(const char *name, const char *type, LONG interval, BOOL notify)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!name || !type || interval < 0) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_MONITOR;
    msg->data.monitor_msg.name = name;
    msg->data.monitor_msg.type = type;
    msg->data.monitor_msg.interval = interval;
    msg->data.monitor_msg.notify = notify;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Get interface status */
LONG BAGetInterfaceStatus(struct BAInterface *interface)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!interface) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_GET_INTERFACE;
    msg->data.interface_msg.interface = interface;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
    return result;
}

/* Get status */
LONG BAGetStatus(struct BAStatus *status)
{
    struct BAMessage *msg;
    LONG result;
    
    /* Check if BonAmi is running */
    result = checkBonAmi();
    if (result != BA_OK) {
        return result;
    }
    
    /* Validate parameters */
    if (!status) {
        return BA_INVALID;
    }
    
    /* Create message */
    msg = AllocVec(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        return BA_NOMEM;
    }
    
    /* Initialize message */
    msg->type = BA_MSG_GET_STATUS;
    msg->data.status_msg.status = status;
    
    /* Send message */
    #ifdef __amigaos4__
    result = IBonAmi->BASendMessage(msg);
    #else
    result = BASendMessage(msg);
    #endif
    
    /* Free message */
    FreeVec(msg);
    
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
    
    msg->msg.mn_ReplyPort = base->replyPort;
    msg->msg.mn_Length = sizeof(struct BAMessage);
    
    PutMsg(base->daemonPort, (struct Message *)msg);
    return BA_OK;
}

/* Wait for reply from daemon */
static LONG waitForReply(struct BABase *base, struct BAMessage *msg)
{
    if (!base || !msg) return BA_BADPARAM;
    
    WaitPort(base->replyPort);
    GetMsg(base->replyPort);
    
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
    if (!type || !type[0]) {
        return BA_BADTYPE;
    }
    
    /* Check for leading underscore */
    if (type[0] != '_') {
        return BA_BADTYPE;
    }
    
    /* Check for .local suffix */
    const char *p = strstr(type, ".local");
    if (!p || p[6] != '\0') {
        return BA_BADTYPE;
    }
    
    return BA_OK;
}

/* Validate service name */
static LONG validateServiceName(const char *name)
{
    if (!name || !name[0]) {
        return BA_BADNAME;
    }
    
    /* Check length */
    if (strlen(name) > 63) {
        return BA_BADNAME;
    }
    
    /* Check characters */
    const char *p;
    for (p = name; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') {
            return BA_BADNAME;
        }
    }
    
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

/* Open library */
struct Library *BAOpenLibrary(ULONG version, struct TagItem *tags)
{
    struct BonAmiBase *base;
    struct TagItem *tag;
    ULONG libVersion = 40;
    BOOL debug = FALSE;
    BOOL memTrack = FALSE;
    
    /* Check version */
    if (version > 40) {
        SetIoErr(ERROR_REQUIRED_ARG_MISSING);
        return NULL;
    }
    
    /* Process tags */
    if (tags) {
        while ((tag = NextTagItem(&tags))) {
            switch (tag->ti_Tag) {
                case LIBTAG_VERSION:
                    libVersion = tag->ti_Data;
                    break;
                case LIBTAG_DEBUG:
                    debug = tag->ti_Data;
                    break;
                case LIBTAG_MEMTRACK:
                    memTrack = tag->ti_Data;
                    break;
            }
        }
    }
    
    /* Open library */
    base = (struct BonAmiBase *)OpenLibrary("bonami.library", libVersion);
    if (!base) {
        return NULL;
    }
    
    /* Initialize base */
    base->debug = debug;
    base->memTrack = memTrack;
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        CloseLibrary((struct Library *)base);
        SetIoErr(ERROR_NO_FREE_STORE);
        return NULL;
    }
    
    /* Set port priority */
    SetMsgPortPriority(base->replyPort, MPRI_NORMAL);
    
    /* Initialize semaphore */
    InitSemaphore(&base->sem);
    
    /* Find BonAmi port */
    base->bonamiPort = FindPort("BonAmi");
    if (!base->bonamiPort) {
        DeleteMsgPort(base->replyPort);
        CloseLibrary((struct Library *)base);
        SetIoErr(ERROR_OBJECT_NOT_FOUND);
        return NULL;
    }
    
    #ifdef __amigaos4__
    /* Get interface */
    base->IBonAmi = (struct BonAmiIFace *)GetInterface((struct Library *)base, "main", 1, NULL);
    if (!base->IBonAmi) {
        DeleteMsgPort(base->replyPort);
        CloseLibrary((struct Library *)base);
        SetIoErr(ERROR_OBJECT_NOT_FOUND);
        return NULL;
    }
    #endif
    
    return (struct Library *)base;
}

/* Close library */
void BACloseLibrary(struct Library *lib)
{
    struct BonAmiBase *base = (struct BonAmiBase *)lib;
    
    if (!base) {
        return;
    }
    
    #ifdef __amigaos4__
    /* Drop interface */
    if (base->IBonAmi) {
        DropInterface((struct Interface *)base->IBonAmi);
        base->IBonAmi = NULL;
    }
    #endif
    
    /* Delete reply port */
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
        base->replyPort = NULL;
    }
    
    /* Close library */
    CloseLibrary(lib);
}

/* Allocate memory with tracking */
static APTR allocTracked(ULONG size, const char *file, LONG line)
{
    struct BonAmiBase *base = (struct BonAmiBase *)SysBase->LibNode;
    APTR memory;
    
    memory = AllocVec(size, MEMF_CLEAR);
    if (memory && base->memTrack) {
        trackMemory(memory, size, file, line);
    }
    
    return memory;
}

/* Free memory with tracking */
static void freeTracked(APTR memory, const char *file, LONG line)
{
    struct BonAmiBase *base = (struct BonAmiBase *)SysBase->LibNode;
    
    if (memory && base->memTrack) {
        untrackMemory(memory, file, line);
    }
    
    FreeVec(memory);
}

/* Track memory allocation */
static void trackMemory(APTR memory, ULONG size, const char *file, LONG line)
{
    struct BonAmiBase *base = (struct BonAmiBase *)SysBase->LibNode;
    
    if (base->debug) {
        printf("Allocated %lu bytes at %p from %s:%ld\n", size, memory, file, line);
    }
}

/* Untrack memory allocation */
static void untrackMemory(APTR memory, const char *file, LONG line)
{
    struct BonAmiBase *base = (struct BonAmiBase *)SysBase->LibNode;
    
    if (base->debug) {
        printf("Freed memory at %p from %s:%ld\n", memory, file, line);
    }
}

/* Send message with timeout */
static LONG sendMessageTimeout(struct BAMessage *msg, ULONG timeout)
{
    struct BonAmiBase *base = (struct BonAmiBase *)SysBase->LibNode;
    ULONG signals;
    LONG result;
    
    /* Send message */
    msg->mn_ReplyPort = base->replyPort;
    PutMsg(base->bonamiPort, (struct Message *)msg);
    
    /* Wait for reply */
    signals = Wait(1 << base->replyPort->mp_SigBit | SIGBREAKF_CTRL_C);
    if (signals & SIGBREAKF_CTRL_C) {
        return BA_ABORTED;
    }
    
    /* Get result */
    result = msg->result;
    
    return result;
} 