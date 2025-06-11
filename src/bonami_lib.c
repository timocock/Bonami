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

#include "../include/bonami.h"
#include "../include/dns.h"

/* Library version */
#define LIB_VERSION    1
#define LIB_REVISION   0

/* Message types for daemon communication */
#define MSG_REGISTER   1
#define MSG_UNREGISTER 2
#define MSG_DISCOVER   3
#define MSG_STOP       4
#define MSG_UPDATE     5
#define MSG_RESOLVE    6
#define MSG_MONITOR    7
#define MSG_CONFIG     8

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
    } data;
};

/* Library base structure */
struct BABase {
    struct Library lib;
    struct SignalSemaphore lock;
    struct MsgPort *replyPort;
    struct Task *mainTask;
    struct List monitors;
    struct List updateCallbacks;
    struct BAConfig config;
    ULONG flags;
};

/* Function prototypes */
static LONG sendMessage(struct BABase *base, struct BAMessage *msg);
static LONG waitForReply(struct BABase *base, struct BAMessage *msg);
static void monitorTask(void *arg);
static BOOL matchFilter(struct BAService *service, struct BAFilter *filter);

/* Library open */
struct Library *OpenLibrary(void)
{
    struct BABase *base;
    
    /* Allocate library base */
    base = (struct BABase *)AllocMem(sizeof(struct BABase), MEMF_CLEAR | MEMF_PUBLIC);
    if (!base) {
        return NULL;
    }
    
    /* Initialize library */
    base->lib.lib_Node.ln_Type = NT_LIBRARY;
    base->lib.lib_Node.ln_Name = "bonami.library";
    base->lib.lib_Flags = LIBF_SUMUSED | LIBF_CHANGED;
    base->lib.lib_Version = LIB_VERSION;
    base->lib.lib_Revision = LIB_REVISION;
    base->lib.lib_IdString = "BonAmi mDNS Library";
    
    /* Initialize semaphore */
    InitSemaphore(&base->lock);
    
    /* Initialize lists */
    NewList(&base->monitors);
    NewList(&base->updateCallbacks);
    
    /* Initialize config */
    memset(&base->config, 0, sizeof(struct BAConfig));
    base->config.discoveryTimeout = 5;
    base->config.resolveTimeout = 2;
    base->config.ttl = 120;
    base->config.autoReconnect = TRUE;
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        FreeMem(base, sizeof(struct BABase));
        return NULL;
    }
    
    /* Find daemon port */
    base->mainTask = FindTask(NULL);
    if (!base->mainTask) {
        DeleteMsgPort(base->replyPort);
        FreeMem(base, sizeof(struct BABase));
        return NULL;
    }
    
    return (struct Library *)base;
}

/* Library close */
void CloseLibrary(void)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    
    /* Free monitors */
    while (!IsListEmpty(&base->monitors)) {
        struct BAMonitor *monitor = (struct BAMonitor *)RemHead(&base->monitors);
        FreeMem(monitor, sizeof(struct BAMonitor));
    }
    
    /* Free update callbacks */
    while (!IsListEmpty(&base->updateCallbacks)) {
        struct BAUpdateCallback *cb = (struct BAUpdateCallback *)RemHead(&base->updateCallbacks);
        FreeMem(cb, sizeof(struct BAUpdateCallback));
    }
    
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
    }
    
    FreeMem(base, sizeof(struct BABase));
}

/* Library expunge */
void ExpungeLibrary(void)
{
    /* Nothing to do here */
}

/* Service registration */
LONG BARegisterService(struct BAService *service)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    LONG result;
    
    if (!service || !service->name[0] || !service->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Obtain semaphore */
    ObtainSemaphore(&base->lock);
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
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
    
    FreeMem(msg, sizeof(struct BAMessage));
    
    /* Release semaphore */
    ReleaseSemaphore(&base->lock);
    
    return result;
}

/* Service unregistration */
LONG BAUnregisterService(const char *name, const char *type)
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
    
    FreeMem(msg, sizeof(struct BAMessage));
    
    return result;
}

/* Start service discovery */
LONG BAStartDiscovery(struct BADiscovery *discovery)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
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
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/* Stop service discovery */
LONG BAStopDiscovery(struct BADiscovery *discovery)
{
    struct BABase *base = (struct BABase *)SysBase->LibNode;
    struct BAMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BA_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
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
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/* Monitor service availability */
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
    monitor = AllocMem(sizeof(struct BAMonitor), MEMF_CLEAR);
    if (!monitor) {
        return BA_NOMEM;
    }
    
    /* Initialize monitor */
    strncpy(monitor->name, name, sizeof(monitor->name) - 1);
    strncpy(monitor->type, type, sizeof(monitor->type) - 1);
    monitor->checkInterval = checkInterval;
    monitor->notifyOffline = notifyOffline;
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
    if (!msg) {
        FreeMem(monitor, sizeof(struct BAMonitor));
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
        FreeMem(monitor, sizeof(struct BAMonitor));
    }
    
    FreeMem(msg, sizeof(struct BAMessage));
    return result;
}

/* Get multiple services */
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
    msg = AllocMem(sizeof(struct BAMessage), MEMF_CLEAR);
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

/* Set configuration */
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

/* Get configuration */
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

    PutMsg(base->mainTask, (struct Message *)msg);
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

/* Resolve service */
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

/* Create TXT record */
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

/* Free TXT record */
void BAFreeTXTRecord(struct BATXTRecord *record)
{
    if (record) {
        FreeMem(record, sizeof(struct BATXTRecord));
    }
}

/* Get interface list */
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

/* Set preferred interface */
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

/* Update service */
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

/* Register service update callback */
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

/* Unregister service update callback */
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