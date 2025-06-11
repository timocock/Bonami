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