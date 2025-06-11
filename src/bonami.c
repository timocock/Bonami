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
#define CONFIG_DIR "ENV:Bonami"
#define CONFIG_LOG_LEVEL "ENV:Bonami/log_level"
#define CONFIG_CACHE_TIMEOUT "ENV:Bonami/cache_timeout"
#define CONFIG_MDNS_TTL "ENV:Bonami/mdns_ttl"
#define CONFIG_INTERFACES "ENV:Bonami/interfaces"
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

/* Service discovery callback structure */
struct BonamiServiceCallback {
    struct Node node;
    char type[256];           /* Service type to discover */
    void (*callback)(struct BonamiService *service, void *userData);
    void *userData;
    BOOL active;
};

/* Service structure */
struct BonamiService {
    char name[256];          /* Service instance name */
    char type[256];          /* Service type (e.g., _smb._tcp.local) */
    char hostname[256];      /* Hostname from SRV record */
    UWORD port;             /* Port from SRV record */
    struct {
        UBYTE *data;        /* TXT record data */
        ULONG length;       /* TXT record length */
    } txt;
    struct in_addr addr;    /* Resolved IP address */
    LONG ttl;              /* Time to live */
    LONG lastUpdate;       /* Last update timestamp */
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
    LONG cacheTimeout;
    LONG mdnsTTL;
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
static LONG BonamiAddServiceDiscovery(const char *type, 
                                    void (*callback)(struct BonamiService *service, void *userData),
                                    void *userData);
static LONG BonamiRemoveServiceDiscovery(const char *type);
static void processDiscoveredService(struct BonamiService *service, 
                                    struct BonamiServiceCallback *callback);

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

/* Add service discovery */
static LONG BonamiAddServiceDiscovery(const char *type, 
                                     void (*callback)(struct BonamiService *service, void *userData),
                                     void *userData)
{
    struct BonamiServiceCallback *cb;
    struct BonamiMessage *msg, *reply;
    
    /* Validate parameters */
    if (!type || !callback) {
        return BONAMI_BADPARAM;
    }
    
    /* Create callback structure */
    cb = AllocMem(sizeof(struct BonamiServiceCallback), MEMF_CLEAR);
    if (!cb) {
        return BONAMI_NOMEM;
    }
    
    /* Initialize callback */
    strncpy(cb->type, type, sizeof(cb->type) - 1);
    cb->callback = callback;
    cb->userData = userData;
    cb->active = TRUE;
    
    /* Create message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        FreeMem(cb, sizeof(struct BonamiServiceCallback));
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->msg.mn_Node.ln_Type = NT_MESSAGE;
    msg->msg.mn_Length = sizeof(struct BonamiMessage);
    msg->msg.mn_ReplyPort = CreateMsgPort();
    if (!msg->msg.mn_ReplyPort) {
        FreeMem(msg, sizeof(struct BonamiMessage));
        FreeMem(cb, sizeof(struct BonamiServiceCallback));
        return BONAMI_ERROR;
    }
    
    msg->type = BONAMI_MSG_DISCOVER;
    strncpy(msg->data.discover_msg.type, type, sizeof(msg->data.discover_msg.type) - 1);
    msg->data.discover_msg.callback = cb;
    
    /* Send message to daemon */
    PutMsg(bonami.port, (struct Message *)msg);
    
    /* Wait for reply */
    reply = (struct BonamiMessage *)WaitPort(msg->msg.mn_ReplyPort);
    if (reply) {
        LONG result = reply->type;
        DeleteMsgPort(msg->msg.mn_ReplyPort);
        FreeMem(msg, sizeof(struct BonamiMessage));
        return result;
    }
    
    DeleteMsgPort(msg->msg.mn_ReplyPort);
    FreeMem(msg, sizeof(struct BonamiMessage));
    return BONAMI_ERROR;
}

/* Remove service discovery */
static LONG BonamiRemoveServiceDiscovery(const char *type)
{
    struct BonamiMessage *msg, *reply;
    
    /* Validate parameters */
    if (!type) {
        return BONAMI_BADPARAM;
    }
    
    /* Create message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->msg.mn_Node.ln_Type = NT_MESSAGE;
    msg->msg.mn_Length = sizeof(struct BonamiMessage);
    msg->msg.mn_ReplyPort = CreateMsgPort();
    if (!msg->msg.mn_ReplyPort) {
        FreeMem(msg, sizeof(struct BonamiMessage));
        return BONAMI_ERROR;
    }
    
    msg->type = BONAMI_MSG_UNDISCOVER;
    strncpy(msg->data.undiscover_msg.type, type, sizeof(msg->data.undiscover_msg.type) - 1);
    
    /* Send message to daemon */
    PutMsg(bonami.port, (struct Message *)msg);
    
    /* Wait for reply */
    reply = (struct BonamiMessage *)WaitPort(msg->msg.mn_ReplyPort);
    if (reply) {
        LONG result = reply->type;
        DeleteMsgPort(msg->msg.mn_ReplyPort);
        FreeMem(msg, sizeof(struct BonamiMessage));
        return result;
    }
    
    DeleteMsgPort(msg->msg.mn_ReplyPort);
    FreeMem(msg, sizeof(struct BonamiMessage));
    return BONAMI_ERROR;
}

/* Process discovered service */
static void processDiscoveredService(struct BonamiService *service, 
                                    struct BonamiServiceCallback *callback)
{
    /* Check if callback is still active */
    if (!callback->active) {
        return;
    }
    
    /* Call user callback */
    callback->callback(service, callback->userData);
}

/* Example usage for SMB share discovery */
void smbShareCallback(struct BonamiService *service, void *userData)
{
    char command[512];
    
    /* Format mount command */
    sprintf(command, "mount smb://%s:%d/%s /Mounts/%s",
            service->hostname,
            service->port,
            service->name,
            service->name);
    
    /* Execute command */
    System(command, 0);
}

/* Example of how to use it */
void discoverSMBShares(void)
{
    /* Add SMB service discovery */
    BonamiAddServiceDiscovery("_smb._tcp.local", smbShareCallback, NULL);
} 