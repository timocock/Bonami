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
#define MSG_STOP        4
#define MSG_RESOLVE     5
#define MSG_UPDATE      6
#define MSG_SHUTDOWN    7
#define MSG_MONITOR     8
#define MSG_CONFIG      9
#define MSG_ENUMERATE   10

/* Memory pool sizes */
#define POOL_PUDDLE_SIZE   8192
#define POOL_THRESHOLD     256
#define POOL_MAX_PUDDLES   32

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

/* Command line template */
static const char *template = "LOG/S,LOGFILE/F,DEBUG/S";

/* Daemon state */
static struct {
    struct List services;
    struct List discoveries;
    struct List monitors;
    struct List cache;
    struct InterfaceState interfaces[MAX_INTERFACES];
    LONG num_interfaces;
    char hostname[256];
    BOOL running;
    BOOL debug;
    LONG log_level;
    BPTR log_file;
    APTR memPool;     /* Memory pool for allocations */
    struct Task *mainTask;
    struct MsgPort *port;
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
static struct DNSQuery *getNextQuery(struct InterfaceState *iface);
static void requeueQuery(struct InterfaceState *iface, struct DNSQuery *query);
static LONG sendQuery(struct InterfaceState *iface, struct DNSQuery *query);
static void cleanupList(struct List *list);

/* Main function */
int main(int argc, char **argv) {
    /* Initialize daemon */
    if (initDaemon() != BA_OK) {
        logMessage(LOG_ERROR, "Failed to initialize daemon\n");
        return RETURN_ERROR;
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
    return RETURN_OK;
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
        cleanupDaemon();
        exit(RETURN_ERROR);
    }
}

/* Initialize daemon */
static LONG initDaemon(void)
{
    struct RDArgs *args;
    LONG result;
    
    /* Parse command line */
    args = ReadArgs(template, NULL, NULL);
    if (!args) {
        printf("Error: Invalid arguments\n");
        return BA_ERROR;
    }
    
    /* Create memory pool */
    bonami.memPool = CreatePool(MEMF_ANY, POOL_PUDDLE_SIZE, POOL_THRESHOLD);
    if (!bonami.memPool) {
        FreeArgs(args);
        return BA_NOMEM;
    }
    
    /* Initialize lists */
    NewList(&bonami.services);
    NewList(&bonami.discoveries);
    NewList(&bonami.monitors);
    NewList(&bonami.cache);
    
    /* Initialize state */
    bonami.num_interfaces = 0;
    bonami.running = TRUE;
    bonami.debug = FALSE;
    bonami.log_level = LOG_INFO;
    bonami.log_file = NULL;
    
    /* Create message port */
    bonami.port = CreateMsgPort();
    if (!bonami.port) {
        DeletePool(bonami.memPool);
        FreeArgs(args);
        return BA_ERROR;
    }
    
    /* Set debug flag */
    if (args->RDA_Flags & RDAF_LOG) {
        bonami.debug = TRUE;
    }
    
    /* Open log file if specified */
    if (args->RDA_Flags & RDAF_LOGFILE) {
        bonami.log_file = Open((char *)args->RDA_LOGFILE, MODE_NEWFILE);
        if (!bonami.log_file) {
            DeleteMsgPort(bonami.port);
            DeletePool(bonami.memPool);
            FreeArgs(args);
            return BA_ERROR;
        }
    }
    
    /* Initialize network */
    result = initInterfaces();
    if (result != BA_OK) {
        if (bonami.log_file) {
            Close(bonami.log_file);
        }
        DeleteMsgPort(bonami.port);
        DeletePool(bonami.memPool);
        FreeArgs(args);
        return result;
    }
    
    /* Resolve hostname */
    result = resolveHostname();
    if (result != BA_OK) {
        if (bonami.log_file) {
            Close(bonami.log_file);
        }
        DeleteMsgPort(bonami.port);
        DeletePool(bonami.memPool);
        FreeArgs(args);
        return result;
    }
    
    FreeArgs(args);
    return BA_OK;
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
        bonami.log_level = atoi(buffer);
    } else {
        /* Set default log level */
        bonami.log_level = LOG_INFO;
        sprintf(buffer, "%ld", bonami.log_level);
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
        while (iface && bonami.num_interfaces < MAX_INTERFACES) {
            strncpy(bonami.interfaces[bonami.num_interfaces].name, 
                   iface, sizeof(bonami.interfaces[0].name) - 1);
            bonami.num_interfaces++;
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
    sprintf(buffer, "%ld", bonami.log_level);
    SetVar(CONFIG_LOG_LEVEL, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save cache timeout */
    sprintf(buffer, "%ld", bonami.cacheTimeout);
    SetVar(CONFIG_CACHE_TIMEOUT, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save mDNS TTL */
    sprintf(buffer, "%ld", bonami.mdnsTTL);
    SetVar(CONFIG_MDNS_TTL, buffer, -1, GVF_GLOBAL_ONLY);
    
    /* Save interface preferences */
    buffer[0] = '\0';
    for (i = 0; i < bonami.num_interfaces; i++) {
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
    /* Close log file */
    if (bonami.log_file) {
        Close(bonami.log_file);
        bonami.log_file = NULL;
    }
    
    /* Cleanup interfaces */
    cleanupInterfaces();
    
    /* Cleanup cache */
    cleanupCache();
    
    /* Cleanup lists */
    while (RemHead(&bonami.services));
    while (RemHead(&bonami.discoveries));
    while (RemHead(&bonami.monitors));
    
    /* Delete message port */
    if (bonami.port) {
        DeleteMsgPort(bonami.port);
        bonami.port = NULL;
    }
    
    /* Delete memory pool */
    if (bonami.memPool) {
        DeletePool(bonami.memPool);
        bonami.memPool = NULL;
    }
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
            /* Validate service name */
            result = validateServiceName(msg->data.register_msg.service.name);
            if (result != BA_OK) {
                msg->data.register_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Validate service type */
            result = validateServiceType(msg->data.register_msg.service.type);
            if (result != BA_OK) {
                msg->data.register_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Validate port */
            result = validatePort(msg->data.register_msg.service.port);
            if (result != BA_OK) {
                msg->data.register_msg.result = result;
                ReplyMsg((struct Message *)msg);
                return;
            }
            
            /* Validate TXT records */
            result = validateTXTRecord(msg->data.register_msg.service.txt);
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
            AddTail(&bonami.services, (struct Node *)service);
            
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
            AddTail(&bonami.services, (struct Node *)discovery);
            
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
            AddTail(&bonami.monitors, (struct Node *)msg->data.monitor_msg.monitor);
            
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
    
    for (node = (struct BAServiceNode *)bonami.services.lh_Head;
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
    
    for (node = (struct BADiscoveryNode *)bonami.services.lh_Head;
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
    for (i = 0; i < bonami.num_interfaces; i++) {
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
    struct DNSRecord *record = NULL;
    char *ptrName = NULL;
    char *nameCopy = NULL;
    
    /* Allocate record */
    record = AllocPooled(sizeof(struct DNSRecord));
    if (!record) {
        return NULL;
    }
    
    /* Create PTR name */
    ptrName = AllocPooled(strlen(type) + 6);
    if (!ptrName) {
        FreePooled(record, sizeof(struct DNSRecord));
        return NULL;
    }
    
    /* Format PTR name */
    sprintf(ptrName, "%s.local", type);
    
    /* Initialize record */
    record->name = ptrName;
    record->type = DNS_TYPE_PTR;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    
    /* Copy name */
    nameCopy = strdup(name);
    if (!nameCopy) {
        FreePooled(ptrName, strlen(type) + 6);
        FreePooled(record, sizeof(struct DNSRecord));
        return NULL;
    }
    record->data.ptr.name = nameCopy;
    
    return record;
}

/* Create an SRV record */
static struct DNSRecord *createSRVRecord(const char *name, UWORD port, const char *host)
{
    struct DNSRecord *record = NULL;
    char *nameCopy = NULL;
    char *hostCopy = NULL;
    
    /* Allocate record */
    record = AllocPooled(sizeof(struct DNSRecord));
    if (!record) {
        return NULL;
    }
    
    /* Copy name */
    nameCopy = strdup(name);
    if (!nameCopy) {
        FreePooled(record, sizeof(struct DNSRecord));
        return NULL;
    }
    record->name = nameCopy;
    
    record->type = DNS_TYPE_SRV;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    record->data.srv.priority = 0;
    record->data.srv.weight = 0;
    record->data.srv.port = port;
    
    /* Copy host */
    hostCopy = strdup(host);
    if (!hostCopy) {
        FreePooled(nameCopy, strlen(name) + 1);
        FreePooled(record, sizeof(struct DNSRecord));
        return NULL;
    }
    record->data.srv.target = hostCopy;
    
    return record;
}

/* Create a TXT record */
static struct DNSRecord *createTXTRecord(const char *name, const struct BATXTRecord *txt)
{
    struct DNSRecord *record = NULL;
    struct BATXTRecord *current;
    LONG length = 0;
    char *data = NULL;
    char *nameCopy = NULL;
    
    /* Allocate record */
    record = AllocPooled(sizeof(struct DNSRecord));
    if (!record) {
        return NULL;
    }
    
    /* Copy name */
    nameCopy = strdup(name);
    if (!nameCopy) {
        FreePooled(record, sizeof(struct DNSRecord));
        return NULL;
    }
    record->name = nameCopy;
    
    record->type = DNS_TYPE_TXT;
    record->class = DNS_CLASS_IN;
    record->ttl = 120;  /* 2 minutes */
    
    /* Calculate total length */
    for (current = (struct BATXTRecord *)txt; current; current = current->next) {
        length += strlen(current->key) + strlen(current->value) + 2;
    }
    
    /* Allocate data */
    data = AllocPooled(length + 1);
    if (!data) {
        FreePooled(nameCopy, strlen(name) + 1);
        FreePooled(record, sizeof(struct DNSRecord));
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
    
    for (record = (struct DNSRecord *)iface->records.lh_Head;
         record->node.ln_Succ;
         record = next) {
        next = (struct DNSRecord *)record->node.ln_Succ;
        
        if (strcmp(record->name, name) == 0 && record->type == type) {
            /* Remove from list */
            Remove((struct Node *)record);
            
            /* Free memory */
            FreePooled(record->name, strlen(record->name) + 1);
            switch (record->type) {
                case DNS_TYPE_PTR:
                    FreePooled(record->data.ptr.name, strlen(record->data.ptr.name) + 1);
                    break;
                case DNS_TYPE_SRV:
                    FreePooled(record->data.srv.target, strlen(record->data.srv.target) + 1);
                    break;
                case DNS_TYPE_TXT:
                    FreePooled(record->data.txt.data, record->data.txt.length + 1);
                    break;
            }
            FreePooled(record, sizeof(struct DNSRecord));
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

/* Network monitor task */
static void networkMonitorTask(void)
{
    struct InterfaceState *iface;
    LONG i;
    
    while (bonami.running) {
        /* Check network status */
        if (checkNetworkStatus() != BA_OK) {
            /* Network is down, wait before retrying */
            Delay(50);
            continue;
        }
        
        /* Check all interfaces */
        for (i = 0; i < bonami.num_interfaces; i++) {
            iface = &bonami.interfaces[i];
            if (checkInterface(iface) != BA_OK) {
                /* Interface is down, wait before retrying */
                Delay(50);
                continue;
            }
            
            /* Update interface services */
            updateInterfaceServices(iface);
        }
        
        /* Wait before next check */
        Delay(50);
    }
}

/* Discovery task */
static void discoveryTask(void)
{
    struct InterfaceState *iface;
    struct DNSQuery *query;
    LONG i;
    
    while (bonami.running) {
        /* Process all interfaces */
        for (i = 0; i < bonami.num_interfaces; i++) {
            iface = &bonami.interfaces[i];
            if (!iface->active) {
                continue;
            }
            
            /* Process service states */
            processServiceStates(iface);
            
            /* Process DNS queries */
            while ((query = getNextQuery(iface)) != NULL) {
                if (processDNSQuery(query) != BA_OK) {
                    /* Query failed, try again later */
                    requeueQuery(iface, query);
                }
            }
        }
        
        /* Wait before next check */
        Delay(10);
    }
}

/* Create multicast socket */
static LONG createMulticastSocket(void)
{
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    LONG sock;
    
    /* Create socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        logMessage(LOG_ERROR, "Failed to create socket: %s", strerror(errno));
        return BA_NETWORK;
    }
    
    /* Set socket options */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        logMessage(LOG_ERROR, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(sock);
        return BA_NETWORK;
    }
    
    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MDNS_PORT);
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logMessage(LOG_ERROR, "Failed to bind socket: %s", strerror(errno));
        close(sock);
        return BA_NETWORK;
    }
    
    /* Join multicast group */
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        logMessage(LOG_ERROR, "Failed to join multicast group: %s", strerror(errno));
        close(sock);
        return BA_NETWORK;
    }
    
    return sock;
}

/* Check network status */
static LONG checkNetworkStatus(void)
{
    struct InterfaceState *iface;
    LONG i;
    
    /* Check if any interface is active */
    for (i = 0; i < bonami.num_interfaces; i++) {
        iface = &bonami.interfaces[i];
        if (iface->active) {
            return BA_OK;
        }
    }
    
    return BA_ERROR;
}

/* Update service records */
static void updateServiceRecords(struct BAServiceNode *service)
{
    struct InterfaceState *iface;
    struct DNSRecord *record;
    LONG i;
    
    /* Update records on all interfaces */
    for (i = 0; i < bonami.num_interfaces; i++) {
        iface = &bonami.interfaces[i];
        if (!iface->active) {
            continue;
        }
        
        /* Remove old records */
        for (record = (struct DNSRecord *)iface->records.lh_Head;
             record->node.ln_Succ;
             record = (struct DNSRecord *)record->node.ln_Succ) {
            if (strcmp(record->name, service->service.name) == 0) {
                removeRecord(iface, record->name, record->type);
            }
        }
        
        /* Add new records */
        record = createPTRRecord(service->service.type, service->service.name);
        if (record) {
            addRecord(iface, record);
            scheduleAnnouncement(iface, record);
        }
        
        record = createSRVRecord(service->service.name, service->service.port, bonami.hostname);
        if (record) {
            addRecord(iface, record);
            scheduleAnnouncement(iface, record);
        }
        
        record = createTXTRecord(service->service.name, service->service.txt);
        if (record) {
            addRecord(iface, record);
            scheduleAnnouncement(iface, record);
        }
    }
}

/* Process DNS query */
static LONG processDNSQuery(struct DNSQuery *query)
{
    struct DNSRecord *record;
    struct DNSQuestion *question;
    struct InterfaceState *iface;
    LONG i;
    
    /* Process all interfaces */
    for (i = 0; i < bonami.num_interfaces; i++) {
        iface = &bonami.interfaces[i];
        if (!iface->active) {
            continue;
        }
        
        /* Check records */
        for (record = (struct DNSRecord *)iface->records.lh_Head;
             record->node.ln_Succ;
             record = (struct DNSRecord *)record->node.ln_Succ) {
            if (strcmp(record->name, query->name) == 0 &&
                record->type == query->type &&
                record->class == query->class) {
                /* Found matching record */
                return BA_OK;
            }
        }
        
        /* Check questions */
        for (question = (struct DNSQuestion *)iface->questions.lh_Head;
             question->node.ln_Succ;
             question = (struct DNSQuestion *)question->node.ln_Succ) {
            if (strcmp(question->name, query->name) == 0 &&
                question->type == query->type &&
                question->class == query->class) {
                /* Found matching question */
                return BA_OK;
            }
        }
    }
    
    return BA_NOTFOUND;
}

/* Validate service name */
static LONG validateServiceName(const char *name)
{
    const char *p;
    BOOL hasDot = FALSE;
    BOOL lastWasDot = TRUE; // Start with dot to prevent leading dots
    
    if (!name || !*name) {
        return BA_BADNAME;
    }
    
    // Check length
    if (strlen(name) > 63) {
        return BA_BADNAME;
    }
    
    // Check each character and label
    for (p = name; *p; p++) {
        if (*p == '.') {
            if (lastWasDot) // No empty labels
                return BA_BADNAME;
            lastWasDot = TRUE;
            hasDot = TRUE;
            continue;
        }
        
        // First character of label must be alphanumeric
        if (lastWasDot && !isalnum(*p))
            return BA_BADNAME;
            
        // Other characters can be alphanumeric or hyphen
        if (!isalnum(*p) && *p != '-')
            return BA_BADNAME;
            
        lastWasDot = FALSE;
    }
    
    // Must have at least one dot
    if (!hasDot)
        return BA_BADNAME;
        
    // Can't end with dot
    if (lastWasDot)
        return BA_BADNAME;
        
    return BA_OK;
}

/* Validate TXT record */
static LONG validateTXTRecord(const struct BATXTRecord *txt)
{
    const struct BATXTRecord *current;
    
    if (!txt)
        return BA_OK; // Empty TXT is valid
        
    for (current = txt; current; current = current->next) {
        // Check key length
        if (!current->key || strlen(current->key) > 63)
            return BA_BADTXT;
            
        // Check value length
        if (!current->value || strlen(current->value) > 255)
            return BA_BADTXT;
            
        // Check key characters
        const char *p;
        for (p = current->key; *p; p++) {
            if (!isalnum(*p) && *p != '-' && *p != '_')
                return BA_BADTXT;
        }
        
        // Check for duplicate keys
        const struct BATXTRecord *check;
        for (check = txt; check != current; check = check->next) {
            if (strcmp(check->key, current->key) == 0)
                return BA_BADTXT;
        }
    }
    
    return BA_OK;
}

/* Validate port number */
static LONG validatePort(UWORD port)
{
    if (port == 0 || port > 65535)
        return BA_BADPORT;
        
    // Check for reserved ports
    if (port < 1024)
        return BA_BADPORT;
        
    return BA_OK;
}

/* Validate DNS record */
static LONG validateDNSRecord(const struct DNSRecord *record)
{
    if (!record || !record->name)
        return BA_BADPARAM;
        
    // Validate name
    LONG result = validateServiceName(record->name);
    if (result != BA_OK)
        return result;
        
    // Validate type
    switch (record->type) {
        case DNS_TYPE_A:
            if (record->rdlength != 4)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_PTR:
            if (record->rdlength > 255)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_SRV:
            if (record->rdlength < 6)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_TXT:
            if (record->rdlength > 255)
                return BA_BADPARAM;
            break;
            
        default:
            return BA_BADPARAM;
    }
    
    return BA_OK;
}

/* Initialize interfaces */
static LONG initInterfaces(void)
{
    struct InterfaceState *iface;
    LONG i;
    
    /* Allocate interface array */
    bonami.interfaces = AllocMem(sizeof(struct InterfaceState) * MAX_INTERFACES,
                               MEMF_CLEAR);
    if (!bonami.interfaces) {
        return BA_NOMEM;
    }
    
    /* Initialize interfaces */
    for (i = 0; i < MAX_INTERFACES; i++) {
        iface = &bonami.interfaces[i];
        
        /* Initialize lists */
        NewList(iface->records);
        NewList(iface->questions);
        NewList(iface->probes);
        NewList(iface->announces);
        
        /* Initialize socket */
        iface->socket = createMulticastSocket();
        if (iface->socket < 0) {
            cleanupInterfaces();
            return BA_ERROR;
        }
        
        /* Set interface active */
        iface->active = TRUE;
    }
    
    bonami.num_interfaces = MAX_INTERFACES;
    return BA_OK;
}

/* Cleanup interfaces */
static void cleanupInterfaces(void)
{
    struct InterfaceState *iface;
    LONG i;
    
    if (!bonami.interfaces) {
        return;
    }
    
    /* Cleanup interfaces */
    for (i = 0; i < bonami.num_interfaces; i++) {
        iface = &bonami.interfaces[i];
        
        /* Close socket */
        if (iface->socket >= 0) {
            close(iface->socket);
        }
        
        /* Free lists */
        cleanupList(iface->records);
        cleanupList(iface->questions);
        cleanupList(iface->probes);
        cleanupList(iface->announces);
    }
    
    /* Free interface array */
    FreeMem(bonami.interfaces, sizeof(struct InterfaceState) * MAX_INTERFACES);
    bonami.interfaces = NULL;
    bonami.num_interfaces = 0;
}

/* Check interface */
static LONG checkInterface(struct InterfaceState *iface)
{
    struct ifreq ifr;
    
    /* Get interface status */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface->name, sizeof(ifr.ifr_name) - 1);
    
    if (ioctl(iface->socket, SIOCGIFFLAGS, &ifr) < 0) {
        return BA_ERROR;
    }
    
    /* Check if interface is up */
    if (!(ifr.ifr_flags & IFF_UP)) {
        return BA_ERROR;
    }
    
    return BA_OK;
}

/* Update interface services */
static void updateInterfaceServices(struct InterfaceState *iface)
{
    struct BAServiceNode *service;
    
    /* Update all services */
    for (service = (struct BAServiceNode *)bonami.services.lh_Head;
         service->node.ln_Succ;
         service = (struct BAServiceNode *)service->node.ln_Succ) {
        updateServiceRecords(service);
    }
}

/* Add cache entry */
static void addCacheEntry(const char *name, WORD type, WORD class,
                         const void *data, LONG length)
{
    struct CacheEntry *entry;
    
    /* Allocate entry */
    entry = AllocMem(sizeof(struct CacheEntry), MEMF_CLEAR);
    if (!entry) {
        return;
    }
    
    /* Initialize entry */
    entry->name = strdup(name);
    if (!entry->name) {
        FreeMem(entry, sizeof(struct CacheEntry));
        return;
    }
    
    entry->type = type;
    entry->class = class;
    entry->data = AllocMem(length, MEMF_CLEAR);
    if (!entry->data) {
        FreeMem(entry->name, strlen(name) + 1);
        FreeMem(entry, sizeof(struct CacheEntry));
        return;
    }
    
    memcpy(entry->data, data, length);
    entry->length = length;
    entry->expires = GetSysTime() + 120;  /* 2 minutes */
    
    /* Add to cache */
    AddTail(&bonami.cache, (struct Node *)entry);
}

/* Remove cache entry */
static void removeCacheEntry(const char *name, WORD type, WORD class)
{
    struct CacheEntry *entry;
    struct CacheEntry *next;
    
    for (entry = (struct CacheEntry *)bonami.cache.lh_Head;
         entry->node.ln_Succ;
         entry = next) {
        next = (struct CacheEntry *)entry->node.ln_Succ;
        
        if (strcmp(entry->name, name) == 0 &&
            entry->type == type &&
            entry->class == class) {
            /* Remove from cache */
            Remove((struct Node *)entry);
            
            /* Free memory */
            FreeMem(entry->name, strlen(entry->name) + 1);
            FreeMem(entry->data, entry->length);
            FreeMem(entry, sizeof(struct CacheEntry));
        }
    }
}

/* Find cache entry */
static struct CacheEntry *findCacheEntry(const char *name, WORD type, WORD class)
{
    struct CacheEntry *entry;
    
    for (entry = (struct CacheEntry *)bonami.cache.lh_Head;
         entry->node.ln_Succ;
         entry = (struct CacheEntry *)entry->node.ln_Succ) {
        if (strcmp(entry->name, name) == 0 &&
            entry->type == type &&
            entry->class == class) {
            return entry;
        }
    }
    
    return NULL;
}

/* Cleanup cache */
static void cleanupCache(void)
{
    struct CacheEntry *entry;
    struct CacheEntry *next;
    
    for (entry = (struct CacheEntry *)bonami.cache.lh_Head;
         entry->node.ln_Succ;
         entry = next) {
        next = (struct CacheEntry *)entry->node.ln_Succ;
        
        /* Remove from cache */
        Remove((struct Node *)entry);
        
        /* Free memory */
        FreeMem(entry->name, strlen(entry->name) + 1);
        FreeMem(entry->data, entry->length);
        FreeMem(entry, sizeof(struct CacheEntry));
    }
}

/* Resolve hostname */
static LONG resolveHostname(void)
{
    struct hostent *host;
    
    /* Get hostname */
    host = gethostbyname(bonami.config.hostname);
    if (!host) {
        return BA_ERROR;
    }
    
    /* Copy address */
    memcpy(&bonami.config.address, host->h_addr, host->h_length);
    
    return BA_OK;
}

/* Check service conflict */
static LONG checkServiceConflict(const char *name, const char *type)
{
    struct InterfaceState *iface;
    struct DNSQuery query;
    LONG i;
    
    /* Initialize query */
    memset(&query, 0, sizeof(query));
    strncpy(query.name, name, sizeof(query.name) - 1);
    query.type = DNS_TYPE_ANY;
    query.class = DNS_CLASS_IN;
    
    /* Check all interfaces */
    for (i = 0; i < bonami.num_interfaces; i++) {
        iface = &bonami.interfaces[i];
        if (!iface->active) {
            continue;
        }
        
        /* Send probe */
        if (sendQuery(iface, &query) != BA_OK) {
            continue;
        }
        
        /* Wait for response */
        Delay(250);
        
        /* Check for response */
        if (processDNSQuery(&query) == BA_OK) {
            return BA_CONFLICT;
        }
    }
    
    return BA_OK;
}

/* Start service announcement */
static void startServiceAnnouncement(struct InterfaceState *iface, struct BAService *service)
{
    struct DNSRecord *record;
    
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
}

/* Process service states */
static void processServiceStates(struct InterfaceState *iface)
{
    struct BAServiceNode *service;
    struct BAServiceNode *next;
    
    for (service = (struct BAServiceNode *)bonami.services.lh_Head;
         service->node.ln_Succ;
         service = next) {
        next = (struct BAServiceNode *)service->node.ln_Succ;
        
        switch (service->state) {
            case 0:  /* Probing */
                if (service->probeCount >= 3) {
                    /* No conflicts found, start announcing */
                    service->state = 1;
                    service->announceCount = 0;
                    startServiceAnnouncement(iface, &service->service);
                }
                break;
                
            case 1:  /* Announcing */
                if (service->announceCount >= 3) {
                    /* Announcement complete */
                    service->state = 2;
                }
                break;
                
            case 2:  /* Stable */
                /* Nothing to do */
                break;
        }
    }
}

/* Process update callbacks */
static void processUpdateCallbacks(struct BAService *service)
{
    struct BAMonitor *monitor;
    
    for (monitor = (struct BAMonitor *)bonami.monitors.lh_Head;
         monitor->node.ln_Succ;
         monitor = (struct BAMonitor *)monitor->node.ln_Succ) {
        if (strcmp(monitor->type, service->type) == 0) {
            /* Call callback */
            monitor->callback(service, monitor->userData);
        }
    }
}

/* Get next query from interface */
static struct DNSQuery *getNextQuery(struct InterfaceState *iface)
{
    struct DNSQuery *query;
    
    /* Get first query */
    query = (struct DNSQuery *)iface->questions.lh_Head;
    if (!query->node.ln_Succ) {
        return NULL;
    }
    
    /* Remove from list */
    Remove((struct Node *)query);
    
    return query;
}

/* Requeue query on interface */
static void requeueQuery(struct InterfaceState *iface, struct DNSQuery *query)
{
    /* Add to end of list */
    AddTail(&iface->questions, (struct Node *)query);
}

/* Send query */
static LONG sendQuery(struct InterfaceState *iface, struct DNSQuery *query)
{
    struct sockaddr_in addr;
    struct DNSMessage msg;
    LONG result;
    
    /* Initialize message */
    memset(&msg, 0, sizeof(msg));
    msg.id = rand();
    msg.flags = DNS_FLAG_QUERY;
    msg.qdcount = 1;
    
    /* Add question */
    strncpy(msg.questions[0].name, query->name, sizeof(msg.questions[0].name) - 1);
    msg.questions[0].type = query->type;
    msg.questions[0].class = query->class;
    
    /* Initialize address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR);
    addr.sin_port = htons(MDNS_PORT);
    
    /* Send message */
    result = sendto(iface->socket, &msg, sizeof(msg), 0,
                   (struct sockaddr *)&addr, sizeof(addr));
    if (result < 0) {
        logMessage(LOG_ERROR, "Failed to send query: %s", strerror(errno));
        return BA_NETWORK;
    }
    
    return BA_OK;
}

/* Cleanup list */
static void cleanupList(struct List *list)
{
    struct Node *node;
    struct Node *next;
    
    for (node = list->lh_Head; node->ln_Succ; node = next) {
        next = node->ln_Succ;
        
        /* Remove from list */
        Remove(node);
        
        /* Free memory */
        FreeMem(node, sizeof(struct Node));
    }
}

/* Log message */
static void logMessage(LONG level, const char *format, ...)
{
    va_list args;
    char buffer[256];
    char *prefix;
    
    /* Check log level */
    if (level > bonami.log_level) {
        return;
    }
    
    /* Get prefix */
    switch (level) {
        case LOG_ERROR:
            prefix = "ERROR: ";
            break;
        case LOG_WARN:
            prefix = "WARNING: ";
            break;
        case LOG_INFO:
            prefix = "INFO: ";
            break;
        case LOG_DEBUG:
            prefix = "DEBUG: ";
            break;
        default:
            prefix = "";
    }
    
    /* Format message */
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    /* Write to log file if specified */
    if (bonami.log_file) {
        Write(bonami.log_file, prefix, strlen(prefix));
        Write(bonami.log_file, buffer, strlen(buffer));
        Write(bonami.log_file, "\n", 1);
    }
    /* Otherwise write to stdout if logging enabled */
    else if (bonami.debug) {
        printf("%s%s\n", prefix, buffer);
    }
}

/* Allocate from pool */
static APTR AllocPooled(ULONG size)
{
    if (!bonami.memPool) return NULL;
    return AllocPooled(bonami.memPool, size);
}

/* Free from pool */
static void FreePooled(APTR memory, ULONG size)
{
    if (!bonami.memPool || !memory) return;
    FreePooled(bonami.memPool, memory, size);
} 