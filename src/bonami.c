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

/* Constants */
#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR "224.0.0.251"
#define MDNS_TTL 120
#define CONFIG_FILE "ENV:Bonami/config"
#define LOG_FILE "ENV:Bonami/log"
#define MAX_INTERFACES 16
#define CACHE_TIMEOUT 120  /* 2 minutes */
#define PROBE_WAIT 250     /* 250ms between probes */
#define PROBE_NUM 3        /* Number of probes */
#define ANNOUNCE_WAIT 1000 /* 1s between announcements */
#define ANNOUNCE_NUM 3     /* Number of announcements */

/* Log levels */
#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

/* Message types */
#define BONAMI_MSG_REGISTER    1
#define BONAMI_MSG_UNREGISTER  2
#define BONAMI_MSG_DISCOVER    3
#define BONAMI_MSG_RESOLVE     4
#define BONAMI_MSG_QUERY       5
#define BONAMI_MSG_UPDATE      6
#define BONAMI_MSG_SHUTDOWN    7

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
    char name[256];
    WORD type;
    WORD class;
    struct DNSRecord record;
    LONG ttl;
    LONG timestamp;
};

/* Service node */
struct BonamiServiceNode {
    struct Node node;
    struct BonamiService service;
    struct InterfaceState *iface;
    LONG state;  /* 0=probing, 1=announcing, 2=active */
    LONG probeCount;
    LONG announceCount;
    LONG lastProbe;
    LONG lastAnnounce;
};

/* Discovery node */
struct BonamiDiscoveryNode {
    struct Node node;
    struct BonamiDiscovery discovery;
    struct Task *task;
    BOOL running;
};

/* Global state */
static struct {
    struct Library *bsdsocket;
    struct Library *roadshow;
    struct Library *utility;
    struct Library *dos;
    struct Library *exec;
    struct List *services;
    struct List *discoveries;
    struct List *cache;
    struct SignalSemaphore lock;
    struct MsgPort *port;
    struct Process *mainProc;
    struct Process *networkProc;
    struct Process *discoveryProc;
    struct InterfaceState interfaces[MAX_INTERFACES];
    LONG numInterfaces;
    BOOL running;
    BOOL networkReady;
    LONG logLevel;
    BPTR logFile;
    char hostname[256];
} bonami;

/* Function prototypes */
static LONG initDaemon(void);
static void cleanupDaemon(void);
static void networkMonitorTask(void);
static void discoveryTask(void);
static void processMessage(struct BonamiMessage *msg);
static LONG createMulticastSocket(void);
static LONG checkNetworkStatus(void);
static struct BonamiServiceNode *findService(const char *name, const char *type);
static struct BonamiDiscoveryNode *findDiscovery(const char *type);
static void updateServiceRecords(struct BonamiServiceNode *service);
static void removeServiceRecords(struct BonamiServiceNode *service);
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
static void startServiceProbing(struct InterfaceState *iface, struct BonamiService *service);
static void startServiceAnnouncement(struct InterfaceState *iface, struct BonamiService *service);
static void processServiceStates(struct InterfaceState *iface);

/* Initialize daemon */
static LONG initDaemon(void)
{
    LONG result;
    
    /* Open required libraries */
    bonami.exec = OpenLibrary("exec.library", 0);
    if (!bonami.exec) {
        return BONAMI_ERROR;
    }
    
    bonami.dos = OpenLibrary("dos.library", 0);
    if (!bonami.dos) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.utility = OpenLibrary("utility.library", 0);
    if (!bonami.utility) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.bsdsocket = OpenLibrary("bsdsocket.library", 0);
    if (!bonami.bsdsocket) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.roadshow = OpenLibrary("roadshow.library", 0);
    if (!bonami.roadshow) {
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
    bonami.discoveries = AllocMem(sizeof(struct List), MEMF_CLEAR);
    bonami.cache = AllocMem(sizeof(struct List), MEMF_CLEAR);
    if (!bonami.services || !bonami.discoveries || !bonami.cache) {
        cleanupDaemon();
        return BONAMI_NOMEM;
    }
    NewList(bonami.services);
    NewList(bonami.discoveries);
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
    
    /* Create log file */
    bonami.logFile = Open(LOG_FILE, MODE_NEWFILE);
    if (!bonami.logFile) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Store main process */
    bonami.mainProc = (struct Process *)FindTask(NULL);
    
    /* Create network monitor task */
    bonami.networkProc = (struct Process *)CreateNewProcTags(
        NP_Name, "Bonami Monitor",
        NP_Entry, networkMonitorTask,
        NP_StackSize, 4096,
        NP_Priority, 0,
        TAG_DONE
    );
    if (!bonami.networkProc) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    bonami.running = TRUE;
    bonami.networkReady = FALSE;
    
    logMessage(LOG_INFO, "Bonami daemon initialized");
    return BONAMI_OK;
}

/* Load configuration */
static LONG loadConfig(void)
{
    BPTR file;
    char buffer[256];
    LONG result = BONAMI_OK;
    
    /* Create config directory if it doesn't exist */
    CreateDir("ENV:Bonami");
    
    /* Open config file */
    file = Open(CONFIG_FILE, MODE_OLDFILE);
    if (file) {
        /* Read log level */
        if (FGets(file, buffer, sizeof(buffer))) {
            bonami.logLevel = atoi(buffer);
        } else {
            bonami.logLevel = LOG_INFO;  /* Default level */
        }
        Close(file);
    } else {
        /* Create default config */
        file = Open(CONFIG_FILE, MODE_NEWFILE);
        if (file) {
            FPrintf(file, "%ld\n", LOG_INFO);
            Close(file);
            bonami.logLevel = LOG_INFO;
        } else {
            result = BONAMI_ERROR;
        }
    }
    
    return result;
}

/* Log message */
static void logMessage(LONG level, const char *format, ...)
{
    char buffer[512];
    va_list args;
    struct DateStamp ds;
    char date[32];
    char time[32];
    
    /* Check log level */
    if (level > bonami.logLevel) {
        return;
    }
    
    /* Get current date and time */
    DateStamp(&ds);
    Amiga2Date(&ds, date);
    sprintf(time, "%02ld:%02ld:%02ld", date->hour, date->min, date->sec);
    
    /* Format message */
    va_start(args, format);
    vsprintf(buffer, format, args);
    va_end(args);
    
    /* Write to log file */
    if (bonami.logFile) {
        FPrintf(bonami.logFile, "[%s] %s\n", time, buffer);
        Flush(bonami.logFile);
    }
}

/* Cleanup daemon */
static void cleanupDaemon(void)
{
    struct BonamiServiceNode *service;
    struct BonamiDiscoveryNode *discovery;
    struct CacheEntry *entry;
    
    /* Stop daemon */
    bonami.running = FALSE;
    
    /* Signal child processes to stop */
    if (bonami.networkProc) {
        Signal((struct Task *)bonami.networkProc, SIGBREAKF_CTRL_C);
    }
    if (bonami.discoveryProc) {
        Signal((struct Task *)bonami.discoveryProc, SIGBREAKF_CTRL_C);
    }
    
    /* Close log file */
    if (bonami.logFile) {
        Close(bonami.logFile);
        bonami.logFile = NULL;
    }
    
    /* Cleanup interfaces */
    cleanupInterfaces();
    
    /* Free services */
    if (bonami.services) {
        while ((service = (struct BonamiServiceNode *)RemHead(bonami.services))) {
            removeServiceRecords(service);
            FreeMem(service, sizeof(struct BonamiServiceNode));
        }
        FreeMem(bonami.services, sizeof(struct List));
    }
    
    /* Free discoveries */
    if (bonami.discoveries) {
        while ((discovery = (struct BonamiDiscoveryNode *)RemHead(bonami.discoveries))) {
            FreeMem(discovery, sizeof(struct BonamiDiscoveryNode));
        }
        FreeMem(bonami.discoveries, sizeof(struct List));
    }
    
    /* Free cache */
    if (bonami.cache) {
        while ((entry = (struct CacheEntry *)RemHead(bonami.cache))) {
            FreeMem(entry, sizeof(struct CacheEntry));
        }
        FreeMem(bonami.cache, sizeof(struct List));
    }
    
    /* Close message port */
    if (bonami.port) {
        DeleteMsgPort(bonami.port);
    }
    
    /* Close libraries */
    if (bonami.roadshow) {
        CloseLibrary(bonami.roadshow);
    }
    if (bonami.bsdsocket) {
        CloseLibrary(bonami.bsdsocket);
    }
    if (bonami.utility) {
        CloseLibrary(bonami.utility);
    }
    if (bonami.dos) {
        CloseLibrary(bonami.dos);
    }
    if (bonami.exec) {
        CloseLibrary(bonami.exec);
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
                processMessage((struct BonamiMessage *)msg);
            }
        }
    }
    
    /* Cleanup */
    cleanupDaemon();
    
    return 0;
} 