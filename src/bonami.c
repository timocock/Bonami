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

/* Service types */
#define SERVICE_TYPE_SMB "_smb._tcp.local"
#define SERVICE_TYPE_HTTP "_http._tcp.local"
#define SERVICE_TYPE_HTTPS "_https._tcp.local"
#define SERVICE_TYPE_SSH "_ssh._tcp.local"
#define SERVICE_TYPE_FTP "_ftp._tcp.local"

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
    char name[32];         /* Interface name */
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
static LONG saveConfig(void);
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
static void handleSMBService(const struct BonamiService *service, void *userData);

/* Handle SMB service discovery */
static void handleSMBService(const struct BonamiService *service, void *userData)
{
    char command[512];
    char workgroup[64] = "WORKGROUP";  /* Default workgroup */
    char *txt;
    LONG i;
    
    /* Extract workgroup from TXT record if available */
    if (service->txt.data && service->txt.length > 0) {
        txt = service->txt.data;
        for (i = 0; i < service->txt.length; i++) {
            if (strncmp(&txt[i], "workgroup=", 10) == 0) {
                strncpy(workgroup, &txt[i + 10], sizeof(workgroup) - 1);
                break;
            }
        }
    }
    
    /* Log the discovered service */
    logMessage(LOG_INFO, "Discovered SMB share: %s on %s (workgroup: %s)",
               service->name, service->hostname, workgroup);
    
    /* Create mount command */
    sprintf(command, "Mount SMB:%s %s %s %s",
            service->name,           /* Share name */
            service->hostname,       /* Server hostname */
            workgroup,              /* Workgroup */
            service->port == 0 ? "445" : service->port);  /* Port */
    
    /* Log the command that would be executed */
    logMessage(LOG_INFO, "Mount command: %s", command);
    
    /* Note: We don't execute the command here, we just provide the information
     * The actual mounting should be handled by the client application
     * This keeps BonAmi focused on service discovery only
     */
}

/* Process incoming message */
static void processMessage(struct BonamiMessage *msg)
{
    struct BonamiMessage *reply;
    struct BonamiServiceNode *service;
    struct BonamiDiscoveryNode *discovery;
    LONG result;
    
    /* Allocate reply message */
    reply = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!reply) {
        return;
    }
    
    /* Set up reply */
    reply->msg.mn_Node.ln_Type = NT_REPLYMSG;
    reply->msg.mn_ReplyPort = msg->msg.mn_ReplyPort;
    reply->msg.mn_Length = sizeof(struct BonamiMessage);
    
    /* Process message */
    switch (msg->type) {
        case BONAMI_MSG_DISCOVER:
            ObtainSemaphore(&bonami.lock);
            
            /* Check if discovery exists */
            discovery = findDiscovery(msg->data.discover_msg.discovery.type);
            if (discovery) {
                reply->type = BONAMI_DUPLICATE;
            } else {
                /* Create new discovery */
                discovery = AllocMem(sizeof(struct BonamiDiscoveryNode), MEMF_CLEAR);
                if (discovery) {
                    memcpy(&discovery->discovery, &msg->data.discover_msg.discovery, 
                           sizeof(struct BonamiDiscovery));
                    discovery->running = TRUE;
                    
                    /* Set up service-specific handler */
                    if (strcmp(discovery->discovery.type, SERVICE_TYPE_SMB) == 0) {
                        discovery->discovery.callback = handleSMBService;
                    }
                    
                    /* Create discovery task */
                    discovery->task = CreateTask("BonAmi Discovery", 0, 
                                               discoveryTask, discovery, 4096);
                    if (discovery->task) {
                        AddTail(bonami.discoveries, (struct Node *)discovery);
                        reply->type = BONAMI_OK;
                    } else {
                        FreeMem(discovery, sizeof(struct BonamiDiscoveryNode));
                        reply->type = BONAMI_ERROR;
                    }
                } else {
                    reply->type = BONAMI_NOMEM;
                }
            }
            
            ReleaseSemaphore(&bonami.lock);
            break;
            
        // ... rest of message handling ...
    }
    
    /* Send reply */
    PutMsg(msg->msg.mn_ReplyPort, (struct Message *)reply);
}

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