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
#define BONAMI_MSG_REGISTER    1
#define BONAMI_MSG_UNREGISTER  2
#define BONAMI_MSG_DISCOVER    3
#define BONAMI_MSG_RESOLVE     4
#define BONAMI_MSG_QUERY       5
#define BONAMI_MSG_UPDATE      6
#define BONAMI_MSG_FILTER      7
#define BONAMI_MSG_MONITOR     8
#define BONAMI_MSG_BATCH       9
#define BONAMI_MSG_CONFIG      10
#define BONAMI_MSG_INTERFACES  11
#define BONAMI_MSG_SET_INTERFACE 12
#define BONAMI_MSG_REGISTER_CALLBACK 13
#define BONAMI_MSG_UNREGISTER_CALLBACK 14

/* Message structure for daemon communication */
struct BonamiMessage {
    struct Message msg;
    ULONG type;
    union {
        struct {
            struct BonamiService service;
        } register_msg;
        struct {
            char name[256];
            char type[256];
        } unregister_msg;
        struct {
            struct BonamiDiscovery discovery;
        } discover_msg;
        struct {
            char name[256];
            char type[256];
            struct BonamiService *result;
        } resolve_msg;
        struct {
            char name[256];
            WORD type;
            WORD class;
            struct DNSRecord *result;
        } query_msg;
        struct {
            char name[256];
            char type[256];
            struct BonamiTXTRecord txt;
        } update_msg;
        struct {
            struct BonamiFilter filter;
        } filter_msg;
        struct {
            struct BonamiMonitor monitor;
        } monitor_msg;
        struct {
            struct BonamiBatch batch;
        } batch_msg;
        struct {
            struct BonamiConfig config;
        } config_msg;
        struct {
            struct BonamiInterface interfaces[256];
            ULONG numInterfaces;
        } interfaces_msg;
        struct {
            char name[256];
        } interface_msg;
        struct {
            const char *name;
            const char *type;
            BonamiServiceCallback callback;
            APTR userData;
        } callback_msg;
    } data;
};

/* Library base structure */
struct BonamiBase {
    struct Library lib;
    struct MsgPort *replyPort;
    struct MsgPort *daemonPort;
    struct List *monitors;      // List of monitored services
    struct BonamiConfig config; // Current configuration
};

/* Function prototypes */
static LONG sendMessage(struct BonamiBase *base, struct BonamiMessage *msg);
static LONG waitReply(struct BonamiBase *base, struct BonamiMessage *msg);
static void monitorTask(void *arg);
static BOOL matchFilter(struct BonamiService *service, struct BonamiFilter *filter);

/* Service registration */
LONG BonamiRegisterService(struct BonamiService *service)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!service || !service->name[0] || !service->type[0]) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_REGISTER;
    memcpy(&msg->data.register_msg.service, service, sizeof(struct BonamiService));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Service unregistration */
LONG BonamiUnregisterService(const char *name, const char *type)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!name || !type) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_UNREGISTER;
    strncpy(msg->data.unregister_msg.name, name, sizeof(msg->data.unregister_msg.name) - 1);
    strncpy(msg->data.unregister_msg.type, type, sizeof(msg->data.unregister_msg.type) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Start service discovery */
LONG BonamiStartDiscovery(struct BonamiDiscovery *discovery)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_DISCOVER;
    memcpy(&msg->data.discover_msg.discovery, discovery, sizeof(struct BonamiDiscovery));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Stop service discovery */
LONG BonamiStopDiscovery(struct BonamiDiscovery *discovery)
{
    /* This is handled by the daemon when the client disconnects */
    return BONAMI_OK;
}

/* Start service discovery with filter */
LONG BonamiStartFilteredDiscovery(const char *type,
                                struct BonamiFilter *filter,
                                BonamiServiceCallback cb,
                                APTR userData)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    struct BonamiDiscovery discovery;
    
    if (!type || !filter || !cb) {
        return BONAMI_BADPARAM;
    }
    
    /* Set up discovery */
    strncpy(discovery.type, type, sizeof(discovery.type) - 1);
    discovery.callback = cb;
    discovery.userData = userData;
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_FILTER;
    memcpy(&msg->data.filter_msg.filter, filter, sizeof(struct BonamiFilter));
    memcpy(&msg->data.discover_msg.discovery, &discovery, sizeof(struct BonamiDiscovery));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Monitor service availability */
LONG BonamiMonitorService(const char *name,
                         const char *type,
                         LONG checkInterval,
                         BOOL notifyOffline)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    struct BonamiMonitor *monitor;
    
    if (!name || !type) {
        return BONAMI_BADPARAM;
    }
    
    /* Create monitor structure */
    monitor = AllocMem(sizeof(struct BonamiMonitor), MEMF_CLEAR);
    if (!monitor) {
        return BONAMI_NOMEM;
    }
    
    /* Initialize monitor */
    strncpy(monitor->name, name, sizeof(monitor->name) - 1);
    strncpy(monitor->type, type, sizeof(monitor->type) - 1);
    monitor->checkInterval = checkInterval;
    monitor->notifyOffline = notifyOffline;
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        FreeMem(monitor, sizeof(struct BonamiMonitor));
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_MONITOR;
    memcpy(&msg->data.monitor_msg.monitor, monitor, sizeof(struct BonamiMonitor));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BONAMI_OK) {
        /* Add to monitor list */
        AddTail(base->monitors, (struct Node *)monitor);
    } else {
        FreeMem(monitor, sizeof(struct BonamiMonitor));
    }
    
    FreeMem(msg, sizeof(struct BonamiMessage));
    return result;
}

/* Get multiple services */
LONG BonamiGetServices(const char *type,
                      struct BonamiService *services,
                      ULONG *numServices)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    struct BonamiBatch batch;
    
    if (!type || !services || !numServices) {
        return BONAMI_BADPARAM;
    }
    
    /* Set up batch */
    batch.services = services;
    batch.numServices = 0;
    batch.maxServices = *numServices;
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_BATCH;
    memcpy(&msg->data.batch_msg.batch, &batch, sizeof(struct BonamiBatch));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BONAMI_OK) {
        *numServices = batch.numServices;
    }
    
    FreeMem(msg, sizeof(struct BonamiMessage));
    return result;
}

/* Set configuration */
LONG BonamiSetConfig(struct BonamiConfig *config)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!config) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_CONFIG;
    memcpy(&msg->data.config_msg.config, config, sizeof(struct BonamiConfig));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BONAMI_OK) {
        /* Update local config */
        memcpy(&base->config, config, sizeof(struct BonamiConfig));
    }
    
    FreeMem(msg, sizeof(struct BonamiMessage));
    return result;
}

/* Get configuration */
LONG BonamiGetConfig(struct BonamiConfig *config)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    
    if (!config) {
        return BONAMI_BADPARAM;
    }
    
    /* Copy current config */
    memcpy(config, &base->config, sizeof(struct BonamiConfig));
    return BONAMI_OK;
}

/* Send message to daemon */
static LONG sendMessage(struct BonamiBase *base, struct BonamiMessage *msg)
{
    /* Set up message */
    msg->msg.mn_Node.ln_Type = NT_MESSAGE;
    msg->msg.mn_ReplyPort = base->replyPort;
    msg->msg.mn_Length = sizeof(struct BonamiMessage);
    
    /* Send to daemon */
    PutMsg(base->daemonPort, (struct Message *)msg);
    
    /* Wait for reply */
    return waitReply(base, msg);
}

/* Wait for reply from daemon */
static LONG waitReply(struct BonamiBase *base, struct BonamiMessage *msg)
{
    struct Message *reply;
    
    /* Wait for reply */
    reply = WaitPort(base->replyPort);
    if (!reply) {
        return BONAMI_ERROR;
    }
    
    /* Get reply */
    reply = GetMsg(base->replyPort);
    if (!reply) {
        return BONAMI_ERROR;
    }
    
    /* Check result */
    LONG result = ((struct BonamiMessage *)reply)->type;
    FreeMem(reply, sizeof(struct BonamiMessage));
    
    return result;
}

/* Match service against filter */
static BOOL matchFilter(struct BonamiService *service, struct BonamiFilter *filter)
{
    if (!filter->txtKey) {
        return TRUE;  // No filter
    }
    
    /* Check TXT records */
    struct BonamiTXTRecord *txt = service->txt;
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
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMonitor *monitor = (struct BonamiMonitor *)arg;
    struct BonamiService service;
    LONG result;
    
    while (monitor->running) {
        /* Check service */
        result = BonamiResolveService(monitor->name, monitor->type, &service);
        
        if (result != BONAMI_OK && monitor->notifyOffline) {
            /* Service is offline, notify */
            if (monitor->callback) {
                monitor->callback(NULL, monitor->userData);
            }
        }
        
        /* Wait for next check */
        Delay(monitor->checkInterval * 50);  // Convert to ticks
    }
}

/* Library open */
struct Library *OpenLibrary(void)
{
    struct BonamiBase *base = (struct BonamiBase *)AllocMem(sizeof(struct BonamiBase), MEMF_CLEAR);
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
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        FreeMem(base, sizeof(struct BonamiBase));
        return NULL;
    }
    
    /* Find daemon port */
    base->daemonPort = FindPort("Bonami");
    if (!base->daemonPort) {
        DeleteMsgPort(base->replyPort);
        FreeMem(base, sizeof(struct BonamiBase));
        return NULL;
    }
    
    /* Initialize monitor list */
    base->monitors = AllocMem(sizeof(struct List), MEMF_CLEAR);
    if (!base->monitors) {
        DeleteMsgPort(base->replyPort);
        FreeMem(base, sizeof(struct BonamiBase));
        return NULL;
    }
    NewList(base->monitors);
    
    /* Initialize default configuration */
    base->config.discoveryTimeout = 5;    // 5 seconds
    base->config.resolveTimeout = 2;      // 2 seconds
    base->config.ttl = 120;               // 2 minutes
    base->config.autoReconnect = TRUE;
    
    return (struct Library *)base;
}

/* Library close */
void CloseLibrary(void)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMonitor *monitor;
    
    /* Stop all monitors */
    while ((monitor = (struct BonamiMonitor *)RemHead(base->monitors))) {
        monitor->running = FALSE;
        FreeMem(monitor, sizeof(struct BonamiMonitor));
    }
    
    if (base->monitors) {
        FreeMem(base->monitors, sizeof(struct List));
    }
    
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
    }
    
    FreeMem(base, sizeof(struct BonamiBase));
}

/* Library expunge */
void ExpungeLibrary(void)
{
    /* Nothing to do here */
}

/* Resolve service */
LONG BonamiResolveService(const char *name,
                         const char *type,
                         struct BonamiService *service)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    struct hostent *host;
    
    if (!name || !type || !service) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_RESOLVE;
    strncpy(msg->data.resolve_msg.name, name, sizeof(msg->data.resolve_msg.name) - 1);
    strncpy(msg->data.resolve_msg.type, type, sizeof(msg->data.resolve_msg.type) - 1);
    msg->data.resolve_msg.result = service;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BONAMI_OK) {
        /* Resolve hostname to IP address */
        host = gethostbyname(service->hostname);
        if (host) {
            memcpy(&service->addr, host->h_addr, sizeof(struct in_addr));
        } else {
            result = BONAMI_RESOLVE;
        }
    }
    
    FreeMem(msg, sizeof(struct BonamiMessage));
    return result;
}

/* Create TXT record */
struct BonamiTXTRecord *BonamiCreateTXTRecord(const char *key,
                                            const char *value)
{
    struct BonamiTXTRecord *record;
    
    if (!key || !value) {
        return NULL;
    }
    
    /* Allocate record */
    record = AllocMem(sizeof(struct BonamiTXTRecord), MEMF_CLEAR);
    if (!record) {
        return NULL;
    }
    
    /* Copy key and value */
    strncpy(record->key, key, sizeof(record->key) - 1);
    strncpy(record->value, value, sizeof(record->value) - 1);
    
    return record;
}

/* Free TXT record */
void BonamiFreeTXTRecord(struct BonamiTXTRecord *record)
{
    if (record) {
        FreeMem(record, sizeof(struct BonamiTXTRecord));
    }
}

/* Get interface list */
LONG BonamiGetInterfaces(struct BonamiInterface *interfaces,
                        ULONG *numInterfaces)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!interfaces || !numInterfaces) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_INTERFACES;
    msg->data.interfaces_msg.interfaces = interfaces;
    msg->data.interfaces_msg.numInterfaces = *numInterfaces;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    if (result == BONAMI_OK) {
        *numInterfaces = msg->data.interfaces_msg.numInterfaces;
    }
    
    FreeMem(msg, sizeof(struct BonamiMessage));
    return result;
}

/* Set preferred interface */
LONG BonamiSetPreferredInterface(const char *interface)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!interface) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_SET_INTERFACE;
    strncpy(msg->data.interface_msg.name, interface, sizeof(msg->data.interface_msg.name) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Update service */
LONG BonamiUpdateService(const char *name,
                        const char *type,
                        struct BonamiTXTRecord *txt)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!name || !type || !txt) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_UPDATE;
    strncpy(msg->data.update_msg.name, name, sizeof(msg->data.update_msg.name) - 1);
    strncpy(msg->data.update_msg.type, type, sizeof(msg->data.update_msg.type) - 1);
    memcpy(&msg->data.update_msg.txt, txt, sizeof(struct BonamiTXTRecord));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Register service update callback */
LONG BonamiRegisterUpdateCallback(const char *name,
                                const char *type,
                                BonamiServiceCallback cb,
                                APTR userData)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!name || !type || !cb) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_REGISTER_CALLBACK;
    strncpy(msg->data.callback_msg.name, name, sizeof(msg->data.callback_msg.name) - 1);
    strncpy(msg->data.callback_msg.type, type, sizeof(msg->data.callback_msg.type) - 1);
    msg->data.callback_msg.callback = cb;
    msg->data.callback_msg.userData = userData;
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Unregister service update callback */
LONG BonamiUnregisterUpdateCallback(const char *name,
                                  const char *type)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!name || !type) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_UNREGISTER_CALLBACK;
    strncpy(msg->data.callback_msg.name, name, sizeof(msg->data.callback_msg.name) - 1);
    strncpy(msg->data.callback_msg.type, type, sizeof(msg->data.callback_msg.type) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
} 