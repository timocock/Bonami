#include <exec/types.h>
#include <exec/memory.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/roadshow.h>
#include <proto/utility.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "bonami.h"
#include "dns.h"

/* Version string */
static const char version[] = "$VER: bonamid 1.0 (01.01.2024)";

/* Constants */
#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR "224.0.0.251"
#define MDNS_TTL 120
#define CONFIG_DIR "ENV:Bonami"
#define CONFIG_LOG_LEVEL "ENV:Bonami/log_level"
#define CONFIG_CACHE_TIMEOUT "ENV:Bonami/cache_timeout"
#define CONFIG_MDNS_TTL "ENV:Bonami/mdns_ttl"
#define CONFIG_INTERFACES "ENV:Bonami/interfaces"
#define MAX_INTERFACES 16
#define CACHE_TIMEOUT 300
#define PROBE_WAIT 250     /* 250ms between probes */
#define PROBE_NUM 3        /* Number of probes */
#define ANNOUNCE_WAIT 1000 /* 1s between announcements */
#define ANNOUNCE_NUM 3     /* Number of announcements */
#define MAX_PACKET_SIZE 4096
#define MAX_SERVICES 256
#define MAX_CACHE_ENTRIES 1024
#define DISCOVERY_TIMEOUT 5
#define RESOLVE_TIMEOUT 2

/* Log levels */
#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

/* Message types */
#define MSG_REGISTER    1
#define MSG_UNREGISTER  2
#define MSG_DISCOVER    3
#define MSG_RESOLVE     4
#define MSG_QUERY       5
#define MSG_UPDATE      6
#define MSG_SHUTDOWN    7
#define MSG_MONITOR     8
#define MSG_CONFIG      9

/* Interface state */
struct InterfaceState {
    struct in_addr addr;
    BOOL active;
    BOOL linkLocal;
    LONG lastCheck;
    struct List *services;  /* Services on this interface */
    struct List *probes;    /* Services being probed */
    struct List *announces; /* Services being announced */
    struct List *records;   /* DNS records on this interface */
    struct List *questions;  /* DNS questions on this interface */
};

/* Cache entry */
struct CacheEntry {
    struct Node node;
    char name[BA_MAX_NAME_LEN];
    WORD type;
    WORD class;
    struct DNSRecord record;
    LONG ttl;
    LONG timestamp;
};

/* Service node */
struct BAServiceNode {
    struct Node node;
    struct BAService service;
    struct InterfaceState *iface;
    LONG state;  /* 0=probing, 1=announcing, 2=active */
    LONG probeCount;
    LONG announceCount;
    LONG lastProbe;
    LONG lastAnnounce;
};

/* Discovery node */
struct BADiscoveryNode {
    struct Node node;
    struct BADiscovery discovery;
    struct Task *task;
    BOOL running;
};

/* Global state */
struct {
    struct Library *execBase;
    struct Library *dosBase;
    struct Library *bsdsocketBase;
    struct List *services;
    struct List *cache;
    struct List *monitors;
    struct List *updateCallbacks;
    struct SignalSemaphore *lock;
    struct MsgPort *port;
    struct Task *mainTask;
    struct Task *networkTask;
    struct Task *discoveryTask;
    struct BAInterface interfaces[MAX_INTERFACES];
    ULONG numInterfaces;
    struct BAConfig config;
    BOOL running;
    BOOL debug;
    struct Library *roadshow;
    struct Library *utility;
    struct Process *mainProc;
    struct Process *networkProc;
    struct Process *discoveryProc;
    struct InterfaceState interfaces[MAX_INTERFACES];
    LONG logLevel;
    char hostname[BA_MAX_NAME_LEN];
    LONG cacheTimeout;
    LONG mdnsTTL;
    ULONG signals;  /* Signal mask for main task */
} bonami;

/* Function prototypes */
static LONG initDaemon(void);
static void cleanupDaemon(void);
static void networkMonitorTask(void);
static void discoveryTask(void);
static void processMessage(struct BAMessage *msg);
static LONG createMulticastSocket(void);
static LONG checkNetworkStatus(void);
static struct BAServiceNode *findService(const char *name, const char *type);
static struct BADiscoveryNode *findDiscovery(const char *type);
static void updateServiceRecords(struct BAServiceNode *service);
static void removeServiceRecords(struct BAServiceNode *service);
static LONG processDNSQuery(struct DNSQuery *query);
static LONG validateServiceName(const char *name);
static LONG validateServiceType(const char *type);
static void logMessage(LONG level, const char *format, ...);
static LONG loadConfig(void);
static LONG initInterfaces(void);
static void cleanupInterfaces(void);
static LONG checkInterface(struct InterfaceState *iface);
static void updateInterfaceServices(struct InterfaceState *iface);
static void addCacheEntry(const char *name, WORD type, WORD class, 
                         const struct DNSRecord *record, LONG ttl);
static void removeCacheEntry(const char *name, WORD type, WORD class);
static struct CacheEntry *findCacheEntry(const char *name, WORD type, WORD class);
static void cleanupCache(void);
static LONG resolveHostname(void);
static LONG checkServiceConflict(const char *name, const char *type);
static void startServiceProbing(struct InterfaceState *iface, struct BAService *service);
static void startServiceAnnouncement(struct InterfaceState *iface, struct BAService *service);
static void processServiceStates(struct InterfaceState *iface);
static void handleSignals(void);
static void processUpdateCallbacks(struct BAService *service);
static struct DNSRecord *createPTRRecord(const char *type, const char *name);
static struct DNSRecord *createSRVRecord(const char *name, UWORD port, const char *host);
static struct DNSRecord *createTXTRecord(const char *name, const struct BATXTRecord *txt);
static struct DNSQuestion *createProbeQuestion(const char *name, const char *type);
static void addRecord(struct InterfaceState *iface, struct DNSRecord *record);
static void addQuestion(struct InterfaceState *iface, struct DNSQuestion *question);
static void removeRecord(struct InterfaceState *iface, const char *name, UWORD type);
static void scheduleAnnouncement(struct InterfaceState *iface, struct DNSRecord *record);
static void scheduleQuery(struct InterfaceState *iface, struct DNSQuestion *question);

/* Main function */
int main(int argc, char **argv) {
    /* Initialize daemon */
    if (initDaemon() != BA_OK) {
        logMessage(LOG_ERROR, "Failed to initialize daemon\n");
        return 1;
    }

    /* Set up signal handling */
    SetSignal(0, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E);

    /* Main loop */
    while (bonami.running) {
        /* Check for signals */
        handleSignals();

        /* Process messages */
        struct Message *msg = WaitPort(bonami.port);
        if (msg) {
            msg = GetMsg(bonami.port);
            if (msg) {
                processMessage((struct BAMessage *)msg);
            }
        }
    }

    /* Cleanup */
    cleanupDaemon();
    return 0;
}

/* Handle signals */
static void handleSignals(void) {
    ULONG signals = SetSignal(0, 0);
    if (signals & SIGBREAKF_CTRL_C) {
        /* Graceful shutdown */
        logMessage(LOG_INFO, "Received shutdown signal\n");
        bonami.running = FALSE;
    } else if (signals & SIGBREAKF_CTRL_D) {
        /* Toggle debug output */
        bonami.debug = !bonami.debug;
        logMessage(LOG_INFO, "Debug output %s\n", bonami.debug ? "enabled" : "disabled");
    } else if (signals & SIGBREAKF_CTRL_E) {
        /* Emergency shutdown */
        logMessage(LOG_ERROR, "Received emergency shutdown signal\n");
        bonami.running = FALSE;
    }
}

/* Initialize daemon */
static LONG initDaemon(void)
{
    LONG result;
    
    /* Open required libraries */
    bonami.execBase = OpenLibrary("exec.library", 0);
    if (!bonami.execBase) {
        return BONAMI_ERROR;
    }
    
    bonami.dosBase = OpenLibrary("dos.library", 0);
    if (!bonami.dosBase) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.bsdsocketBase = OpenLibrary("bsdsocket.library", 0);
    if (!bonami.bsdsocketBase) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.roadshow = OpenLibrary("roadshow.library", 0);
    if (!bonami.roadshow) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.utility = OpenLibrary("utility.library", 0);
    if (!bonami.utility) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Initialize socket library */
    if (SocketBaseTags(SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno))), (ULONG)&errno,
                       SBTM_SETVAL(SBTC_LOGTAGPTR), (ULONG)"Bonami",
                       TAG_DONE)) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Create message port */
    bonami.port = CreateMsgPort();
    if (!bonami.port) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Initialize lists */
    bonami.services = AllocMem(sizeof(struct List), MEMF_CLEAR);
    bonami.cache = AllocMem(sizeof(struct List), MEMF_CLEAR);
    if (!bonami.services || !bonami.cache) {
        cleanupDaemon();
        return BONAMI_NOMEM;
    }
    NewList(bonami.services);
    NewList(bonami.cache);
    
    /* Initialize semaphore */
    InitSemaphore(&bonami.lock);
    
    /* Load configuration */
    result = loadConfig();
    if (result != BONAMI_OK) {
        cleanupDaemon();
        return result;
    }
    
    /* Initialize interfaces */
    result = initInterfaces();
    if (result != BONAMI_OK) {
        cleanupDaemon();
        return result;
    }
    
    /* Resolve hostname */
    result = resolveHostname();
    if (result != BONAMI_OK) {
        cleanupDaemon();
        return result;
    }
    
    /* Store main process */
    bonami.mainProc = (struct Process *)FindTask(NULL);
    
    /* Set up signal handling */
    bonami.signals = SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E;
    SetSignal(0, bonami.signals);
    
    /* Create network monitor task */
    bonami.networkProc = (struct Process *)CreateNewProcTags(
        NP_Name, "Bonami Monitor",
        NP_Entry, networkMonitorTask,
        NP_StackSize, 4096,
        NP_Priority, 0,
        TAG_DONE);
    if (!bonami.networkProc) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Create discovery task */
    bonami.discoveryProc = (struct Process *)CreateNewProcTags(
        NP_Name, "Bonami Discovery",
        NP_Entry, discoveryTask,
        NP_StackSize, 4096,
        NP_Priority, 0,
        TAG_DONE);
    if (!bonami.discoveryProc) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.running = TRUE;
    return BONAMI_OK;
}

/* Load configuration */
static LONG loadConfig(void)
{
    BPTR lock;
    char buffer[256];
    LONG result = BONAMI_OK;
    
    /* Create config directory if it doesn't exist */
    lock = Lock(CONFIG_DIR, ACCESS_READ);
    if (!lock) {
        /* Directory doesn't exist, create it */
        if (!CreateDir(CONFIG_DIR)) {
            return BONAMI_ERROR;
        }
    } else {
        UnLock(lock);
    }
    
    /* Load log level */
    if (GetVar(CONFIG_LOG_LEVEL, buffer, sizeof(buffer), 0) > 0) {
        bonami.logLevel = atoi(buffer);
    } else {
        /* Set default log level */
        bonami.logLevel = LOG_INFO;
        sprintf(buffer, "%ld", bonami.logLevel);
        SetVar(CONFIG_LOG_LEVEL, buffer, -1, GVF_GLOBAL_ONLY);
    }
    
    /* Load cache timeout */
    if (GetVar(CONFIG_CACHE_TIMEOUT, buffer, sizeof(buffer), 0) > 0) {
        bonami.cacheTimeout = atoi(buffer);
    } else {
        /* Set default cache timeout */
        bonami.cacheTimeout = CACHE_TIMEOUT;
        sprintf(buffer, "%ld", bonami.cacheTimeout);
        SetVar(CONFIG_CACHE_TIMEOUT, buffer, -1, GVF_GLOBAL_ONLY);
    }
    
    /* Load mDNS TTL */
    if (GetVar(CONFIG_MDNS_TTL, buffer, sizeof(buffer), 0) > 0) {
        bonami.mdnsTTL = atoi(buffer);
    } else {
        /* Set default mDNS TTL */
        bonami.mdnsTTL = MDNS_TTL;
        sprintf(buffer, "%ld", bonami.mdnsTTL);
        SetVar(CONFIG_MDNS_TTL, buffer, -1, GVF_GLOBAL_ONLY);
    }
    
    /* Load interface preferences */
    if (GetVar(CONFIG_INTERFACES, buffer, sizeof(buffer), 0) > 0) {
        /* Parse interface list */
        char *iface = strtok(buffer, ",");
        while (iface && bonami.numInterfaces < MAX_INTERFACES) {
            strncpy(bonami.interfaces[bonami.numInterfaces].name, 
                   iface, sizeof(bonami.interfaces[0].name) - 1);
            bonami.numInterfaces++;
            iface = strtok(NULL, ",");
        }
    }
    
    return result;
}

/* Save configuration */
static LONG saveConfig(void)
{
    char buffer[256];
    LONG i;
    
    /* Save log level */
    sprintf(buffer, "%ld", bonami.logLevel);
    SetVar(CONFIG_LOG_LEVEL, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save cache timeout */
    sprintf(buffer, "%ld", bonami.cacheTimeout);
    SetVar(CONFIG_CACHE_TIMEOUT, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save mDNS TTL */
    sprintf(buffer, "%ld", bonami.mdnsTTL);
    SetVar(CONFIG_MDNS_TTL, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save interface preferences */
    buffer[0] = '\0';
    for (i = 0; i < bonami.numInterfaces; i++) {
        if (i > 0) {
            strcat(buffer, ",");
        }
        strcat(buffer, bonami.interfaces[i].name);
    }
    SetVar(CONFIG_INTERFACES, buffer, -1, GVF_GLOBAL_ONLY);
    
    return BONAMI_OK;
}

/* Cleanup daemon */
static void cleanupDaemon(void)
{
    struct BAServiceNode *service;
    struct BADiscoveryNode *discovery;
    struct CacheEntry *entry;
    
    /* Stop tasks */
    if (bonami.networkProc) {
        Signal((struct Task *)bonami.networkProc, SIGBREAKF_CTRL_C);
    }
    if (bonami.discoveryProc) {
        Signal((struct Task *)bonami.discoveryProc, SIGBREAKF_CTRL_C);
    }
    
    /* Clean up services */
    if (bonami.services) {
        while ((service = (struct BAServiceNode *)RemHead(bonami.services))) {
            FreeMem(service, sizeof(struct BAServiceNode));
        }
        FreeMem(bonami.services, sizeof(struct List));
    }
    
    /* Clean up cache */
    if (bonami.cache) {
        while ((entry = (struct CacheEntry *)RemHead(bonami.cache))) {
            FreeMem(entry, sizeof(struct CacheEntry));
        }
        FreeMem(bonami.cache, sizeof(struct List));
    }
    
    /* Clean up interfaces */
    cleanupInterfaces();
    
    /* Close message port */
    if (bonami.port) {
        DeleteMsgPort(bonami.port);
    }
    
    /* Close libraries */
    if (bonami.roadshow) {
        CloseLibrary(bonami.roadshow);
    }
    if (bonami.bsdsocketBase) {
        CloseLibrary(bonami.bsdsocketBase);
    }
    if (bonami.utility) {
        CloseLibrary(bonami.utility);
    }
    if (bonami.dosBase) {
        CloseLibrary(bonami.dosBase);
    }
    if (bonami.execBase) {
        CloseLibrary(bonami.execBase);
    }
}

/* Main function */
int main(void)
{
    struct Message *msg;
    LONG result;
    
    /* Initialize daemon */
    result = initDaemon();
    if (result != BONAMI_OK) {
        return 1;
    }
    
    /* Main loop */
    while (bonami.running) {
        /* Wait for message */
        msg = WaitPort(bonami.port);
        if (msg) {
            msg = GetMsg(bonami.port);
            if (msg) {
                processMessage((struct BAMessage *)msg);
            }
        }
    }
    
    /* Cleanup */
    cleanupDaemon();
    
    return 0;
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

/* Process incoming messages */
static void processMessage(struct BAMessage *msg)
{
    struct BAServiceNode *service;
    struct BADiscoveryNode *discovery;
    LONG result;
    
    switch (msg->type) {
        case MSG_REGISTER:
            /* Validate service type */
            result = validateServiceType(msg->data.register_msg.service.type);
            if (result != BA_OK) {
                msg->data.register_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Check for duplicate service */
            service = findService(msg->data.register_msg.service.name,
                                msg->data.register_msg.service.type);
            if (service) {
                msg->data.register_msg.result = BA_DUPLICATE;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Create service node */
            service = AllocMem(sizeof(struct BAServiceNode), MEMF_CLEAR);
            if (!service) {
                msg->data.register_msg.result = BA_NOMEM;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Initialize service */
            memcpy(&service->service, &msg->data.register_msg.service,
                   sizeof(struct BAService));
            service->state = 0;  /* Start probing */
            service->probeCount = 0;
            service->announceCount = 0;
            
            /* Add to service list */
            AddTail(bonami.services, (struct Node *)service);
            
            /* Start probing */
            startServiceProbing(&bonami.interfaces[0], &service->service);
            
            msg->data.register_msg.result = BA_OK;
            break;
            
        case MSG_UNREGISTER:
            /* Find service */
            service = findService(msg->data.unregister_msg.name,
                                msg->data.unregister_msg.type);
            if (!service) {
                msg->data.unregister_msg.result = BA_NOTFOUND;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Remove service records */
            removeServiceRecords(service);
            
            /* Remove from list */
            Remove((struct Node *)service);
            FreeMem(service, sizeof(struct BAServiceNode));
            
            msg->data.unregister_msg.result = BA_OK;
            break;
            
        case MSG_DISCOVER:
            /* Validate service type */
            result = validateServiceType(msg->data.discover_msg.type);
            if (result != BA_OK) {
                msg->data.discover_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Create discovery node */
            discovery = AllocMem(sizeof(struct BADiscoveryNode), MEMF_CLEAR);
            if (!discovery) {
                msg->data.discover_msg.result = BA_NOMEM;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Initialize discovery */
            strncpy(discovery->discovery.type, msg->data.discover_msg.type,
                    sizeof(discovery->discovery.type) - 1);
            discovery->discovery.services = msg->data.discover_msg.services;
            discovery->running = TRUE;
            
            /* Add to discovery list */
            AddTail(bonami.services, (struct Node *)discovery);
            
            msg->data.discover_msg.result = BA_OK;
            break;
            
        case MSG_STOP:
            /* Find discovery */
            discovery = findDiscovery(msg->data.discover_msg.type);
            if (!discovery) {
                msg->data.discover_msg.result = BA_NOTFOUND;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Stop discovery */
            discovery->running = FALSE;
            
            /* Remove from list */
            Remove((struct Node *)discovery);
            FreeMem(discovery, sizeof(struct BADiscoveryNode));
            
            msg->data.discover_msg.result = BA_OK;
            break;
            
        case MSG_MONITOR:
            /* Validate service type */
            result = validateServiceType(msg->data.monitor_msg.type);
            if (result != BA_OK) {
                msg->data.monitor_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Add monitor */
            AddTail(bonami.monitors, (struct Node *)msg->data.monitor_msg.monitor);
            
            msg->data.monitor_msg.result = BA_OK;
            break;
            
        case MSG_CONFIG:
            /* Update configuration */
            memcpy(&bonami.config, &msg->data.config_msg.config,
                   sizeof(struct BAConfig));
            
            msg->data.config_msg.result = BA_OK;
            break;
            
        case MSG_SHUTDOWN:
            bonami.running = FALSE;
            break;
    }
    
    /* Reply to message */
    ReplyMsg((struct Message *)msg);
}

/* Find a service by name and type */
static struct BAServiceNode *findService(const char *name, const char *type)
{
    struct BAServiceNode *node;
    
    for (node = (struct BAServiceNode *)bonami.services->lh_Head;
         node->node.ln_Succ;
         node = (struct BAServiceNode *)node->node.ln_Succ) {
        if (strcmp(node->service.name, name) == 0 &&
            strcmp(node->service.type, type) == 0) {
            return node;
        }
    }
    
    return NULL;
}

/* Find a discovery by type */
static struct BADiscoveryNode *findDiscovery(const char *type)
{
    struct BADiscoveryNode *node;
    
    for (node = (struct BADiscoveryNode *)bonami.services->lh_Head;
         node->node.ln_Succ;
         node = (struct BADiscoveryNode *)node->node.ln_Succ) {
        if (strcmp(node->discovery.type, type) == 0) {
            return node;
        }
    }
    
    return NULL;
}

/* Remove all records for a service */
static void removeServiceRecords(struct BAServiceNode *service)
{
    struct InterfaceState *iface;
    LONG i;
    
    /* Remove from all interfaces */
    for (i = 0; i < bonami.numInterfaces; i++) {
        iface = &bonami.interfaces[i];
        if (iface->active) {
            /* Remove PTR record */
            removeRecord(iface, service->service.type, DNS_TYPE_PTR);
            
            /* Remove SRV record */
            removeRecord(iface, service->service.name, DNS_TYPE_SRV);
            
            /* Remove TXT record */
            removeRecord(iface, service->service.name, DNS_TYPE_TXT);
        }
    }
}

/* Start probing for a service */
static void startServiceProbing(struct InterfaceState *iface, struct BAService *service)
{
    struct DNSRecord *record;
    struct DNSQuestion *question;
    LONG i;
    
    /* Create PTR record */
    record = createPTRRecord(service->type, service->name);
    if (!record) {
        return;
    }
    
    /* Add to interface */
    addRecord(iface, record);
    
    /* Create SRV record */
    record = createSRVRecord(service->name, service->port, service->host);
    if (!record) {
        return;
    }
    
    /* Add to interface */
    addRecord(iface, record);
    
    /* Create TXT record */
    record = createTXTRecord(service->name, service->txt);
    if (!record) {
        return;
    }
    
    /* Add to interface */
    addRecord(iface, record);
    
    /* Create probe questions */
    for (i = 0; i < 3; i++) {
        question = createProbeQuestion(service->name, service->type);
        if (!question) {
            continue;
        }
        
        /* Add to interface */
        addQuestion(iface, question);
    }
}

/* Create a PTR record */
static struct DNSRecord *createPTRRecord(const char *type, const char *name)
{
    struct DNSRecord *record;
    char *ptrName;
    
    /* Allocate record */
    record = AllocMem(sizeof(struct DNSRecord), MEMF_CLEAR);
    if (!record) {
        return NULL;
    }
    
    /* Create PTR name */
    ptrName = AllocMem(strlen(type) + 6, MEMF_CLEAR);
    if (!ptrName) {
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    /* Format PTR name */
    sprintf(ptrName, "%s.local", type);
    
    /* Initialize record */
    record->name = ptrName;
    record->type = DNS_TYPE_PTR;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    record->data.ptr.name = strdup(name);
    if (!record->data.ptr.name) {
        FreeMem(ptrName, strlen(type) + 6);
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    return record;
}

/* Create an SRV record */
static struct DNSRecord *createSRVRecord(const char *name, UWORD port, const char *host)
{
    struct DNSRecord *record;
    
    /* Allocate record */
    record = AllocMem(sizeof(struct DNSRecord), MEMF_CLEAR);
    if (!record) {
        return NULL;
    }
    
    /* Initialize record */
    record->name = strdup(name);
    if (!record->name) {
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    record->type = DNS_TYPE_SRV;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    record->data.srv.priority = 0;
    record->data.srv.weight = 0;
    record->data.srv.port = port;
    record->data.srv.target = strdup(host);
    if (!record->data.srv.target) {
        FreeMem(record->name, strlen(name) + 1);
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    return record;
}

/* Create a TXT record */
static struct DNSRecord *createTXTRecord(const char *name, const struct BATXTRecord *txt)
{
    struct DNSRecord *record;
    struct BATXTRecord *current;
    LONG length = 0;
    char *data;
    
    /* Allocate record */
    record = AllocMem(sizeof(struct DNSRecord), MEMF_CLEAR);
    if (!record) {
        return NULL;
    }
    
    /* Initialize record */
    record->name = strdup(name);
    if (!record->name) {
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    record->type = DNS_TYPE_TXT;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    
    /* Calculate total length */
    for (current = (struct BATXTRecord *)txt; current; current = current->next) {
        length += strlen(current->key) + strlen(current->value) + 2;
    }
    
    /* Allocate data */
    data = AllocMem(length + 1, MEMF_CLEAR);
    if (!data) {
        FreeMem(record->name, strlen(name) + 1);
        FreeMem(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    /* Format data */
    for (current = (struct BATXTRecord *)txt; current; current = current->next) {
        strcat(data, current->key);
        strcat(data, "=");
        strcat(data, current->value);
        if (current->next) {
            strcat(data, " ");
        }
    }
    
    record->data.txt.data = data;
    record->data.txt.length = length;
    
    return record;
}

/* Create a probe question */
static struct DNSQuestion *createProbeQuestion(const char *name, const char *type)
{
    struct DNSQuestion *question;
    char *questionName;
    
    /* Allocate question */
    question = AllocMem(sizeof(struct DNSQuestion), MEMF_CLEAR);
    if (!question) {
        return NULL;
    }
    
    /* Create question name */
    questionName = AllocMem(strlen(name) + strlen(type) + 8, MEMF_CLEAR);
    if (!questionName) {
        FreeMem(question, sizeof(struct DNSQuestion));
        return NULL;
    }
    
    /* Format question name */
    sprintf(questionName, "%s.%s.local", name, type);
    
    /* Initialize question */
    question->name = questionName;
    question->type = DNS_TYPE_ANY;
    question->class = DNS_CLASS_IN;
    question->unicast = FALSE;
    
    return question;
}

/* Add a record to an interface */
static void addRecord(struct InterfaceState *iface, struct DNSRecord *record)
{
    /* Add to record list */
    AddTail(iface->records, (struct Node *)record);
    
    /* Schedule announcement */
    scheduleAnnouncement(iface, record);
}

/* Add a question to an interface */
static void addQuestion(struct InterfaceState *iface, struct DNSQuestion *question)
{
    /* Add to question list */
    AddTail(iface->questions, (struct Node *)question);
    
    /* Schedule query */
    scheduleQuery(iface, question);
}

/* Remove a record from an interface */
static void removeRecord(struct InterfaceState *iface, const char *name, UWORD type)
{
    struct DNSRecord *record;
    struct DNSRecord *next;
    
    for (record = (struct DNSRecord *)iface->records->lh_Head;
         record->node.ln_Succ;
         record = next) {
        next = (struct DNSRecord *)record->node.ln_Succ;
        
        if (strcmp(record->name, name) == 0 && record->type == type) {
            /* Remove from list */
            Remove((struct Node *)record);
            
            /* Free memory */
            FreeMem(record->name, strlen(record->name) + 1);
            if (record->type == DNS_TYPE_PTR) {
                FreeMem(record->data.ptr.name, strlen(record->data.ptr.name) + 1);
            } else if (record->type == DNS_TYPE_SRV) {
                FreeMem(record->data.srv.target, strlen(record->data.srv.target) + 1);
            } else if (record->type == DNS_TYPE_TXT) {
                FreeMem(record->data.txt.data, record->data.txt.length + 1);
            }
            FreeMem(record, sizeof(struct DNSRecord));
        }
    }
}

/* Schedule a record announcement */
static void scheduleAnnouncement(struct InterfaceState *iface, struct DNSRecord *record)
{
    struct Announcement *announce;
    
    /* Allocate announcement */
    announce = AllocMem(sizeof(struct Announcement), MEMF_CLEAR);
    if (!announce) {
        return;
    }
    
    /* Initialize announcement */
    announce->record = record;
    announce->count = 0;
    announce->nextTime = GetSysTime() + 1;  /* Start in 1 second */
    
    /* Add to announcement list */
    AddTail(iface->announces, (struct Node *)announce);
}

/* Schedule a question query */
static void scheduleQuery(struct InterfaceState *iface, struct DNSQuestion *question)
{
    struct Probe *probe;
    
    /* Allocate probe */
    probe = AllocMem(sizeof(struct Probe), MEMF_CLEAR);
    if (!probe) {
        return;
    }
    
    /* Initialize probe */
    probe->question = question;
    probe->count = 0;
    probe->nextTime = GetSysTime() + 1;  /* Start in 1 second */
    
    /* Add to probe list */
    AddTail(iface->probes, (struct Node *)probe);
} 