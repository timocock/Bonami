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
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/utility.h>
#include <proto/roadshow.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <utility/tagitem.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>

#include "bonami.h"
#include "dns.h"

/* Constants */
#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR "224.0.0.251"
#define MDNS_TTL 120
#define CONFIG_FILE "ENV:Bonami/config"
#define PID_FILE "ENV:Bonami/pid"
#define LOG_FILE "ENV:Bonami/log"
#define MAX_INTERFACES 16
#define CACHE_TIMEOUT 120  /* 2 minutes */

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
    LONG lastCheck;
    struct List *services;  /* Services on this interface */
};

/* Cache entry */
struct CacheEntry {
    struct Node node;
    char name[256];
    WORD type;
    WORD class;
    struct DNSRecord record;
    LONG ttl;
    LONG expires;
};

/* Message structure */
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
    } data;
};

/* Service node structure */
struct BonamiServiceNode {
    struct Node node;
    struct BonamiService service;
    ULONG lastUpdate;
    struct DNSRecord *records;  /* DNS records for this service */
    ULONG numRecords;
};

/* Discovery node structure */
struct BonamiDiscoveryNode {
    struct Node node;
    struct BonamiDiscovery discovery;
    struct Task *task;
    BOOL running;
    LONG sock;  /* Multicast socket */
};

/* SRV record data structure */
struct SRVRecord {
    UWORD priority;
    UWORD weight;
    UWORD port;
    char target[256];
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
    LONG logFile;
    char hostname[256];
} bonami;

/* DNS query structure */
struct DNSQuery {
    char name[256];
    WORD type;
    WORD class;
    struct DNSRecord *result;
    ULONG resultLen;
    struct sockaddr_in from;
};

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
static void signalHandler(LONG sig);
static LONG writePIDFile(void);
static void removePIDFile(void);
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

/* Initialize interfaces */
static LONG initInterfaces(void)
{
    struct ifreq ifr;
    LONG sock;
    LONG i;
    
    /* Create socket for ioctl */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return BONAMI_ERROR;
    }
    
    /* Get interface list */
    for (i = 0; i < MAX_INTERFACES; i++) {
        ifr.ifr_ifindex = i;
        if (ioctl(sock, SIOCGIFNAME, &ifr) < 0) {
            break;
        }
        
        /* Get interface address */
        if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
            continue;
        }
        
        /* Initialize interface state */
        bonami.interfaces[bonami.numInterfaces].addr = 
            ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
        bonami.interfaces[bonami.numInterfaces].active = FALSE;
        bonami.interfaces[bonami.numInterfaces].lastCheck = 0;
        bonami.interfaces[bonami.numInterfaces].services = 
            AllocMem(sizeof(struct List), MEMF_CLEAR);
        if (bonami.interfaces[bonami.numInterfaces].services) {
            NewList(bonami.interfaces[bonami.numInterfaces].services);
            bonami.numInterfaces++;
        }
    }
    
    CloseSocket(sock);
    return BONAMI_OK;
}

/* Cleanup interfaces */
static void cleanupInterfaces(void)
{
    LONG i;
    
    for (i = 0; i < bonami.numInterfaces; i++) {
        if (bonami.interfaces[i].services) {
            struct Node *node, *next;
            for (node = bonami.interfaces[i].services->lh_Head; 
                 (next = node->ln_Succ); node = next) {
                Remove(node);
                FreeMem(node, sizeof(struct BonamiServiceNode));
            }
            FreeMem(bonami.interfaces[i].services, sizeof(struct List));
        }
    }
    bonami.numInterfaces = 0;
}

/* Check interface status */
static LONG checkInterface(struct InterfaceState *iface)
{
    struct ifreq ifr;
    LONG sock;
    
    /* Create socket for ioctl */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return BONAMI_ERROR;
    }
    
    /* Get interface flags */
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);  /* TODO: Get actual interface name */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        CloseSocket(sock);
        return BONAMI_ERROR;
    }
    
    /* Check if interface is up */
    if (ifr.ifr_flags & IFF_UP) {
        if (!iface->active) {
            iface->active = TRUE;
            updateInterfaceServices(iface);
        }
    } else {
        iface->active = FALSE;
    }
    
    CloseSocket(sock);
    return BONAMI_OK;
}

/* Update interface services */
static void updateInterfaceServices(struct InterfaceState *iface)
{
    struct BonamiServiceNode *service;
    
    /* Update all services on this interface */
    for (service = (struct BonamiServiceNode *)iface->services->lh_Head;
         service->node.ln_Succ;
         service = (struct BonamiServiceNode *)service->node.ln_Succ) {
        updateServiceRecords(service);
    }
}

/* Add cache entry */
static void addCacheEntry(const char *name, WORD type, WORD class, 
                         const struct DNSRecord *record, LONG ttl)
{
    struct CacheEntry *entry;
    
    /* Remove existing entry if any */
    removeCacheEntry(name, type, class);
    
    /* Create new entry */
    entry = AllocMem(sizeof(struct CacheEntry), MEMF_CLEAR);
    if (entry) {
        strncpy(entry->name, name, sizeof(entry->name) - 1);
        entry->type = type;
        entry->class = class;
        memcpy(&entry->record, record, sizeof(struct DNSRecord));
        entry->ttl = ttl;
        entry->expires = GetSysTime() + ttl;
        
        /* Add to cache */
        AddTail(bonami.cache, (struct Node *)entry);
    }
}

/* Remove cache entry */
static void removeCacheEntry(const char *name, WORD type, WORD class)
{
    struct CacheEntry *entry;
    
    entry = findCacheEntry(name, type, class);
    if (entry) {
        Remove((struct Node *)entry);
        FreeMem(entry, sizeof(struct CacheEntry));
    }
}

/* Find cache entry */
static struct CacheEntry *findCacheEntry(const char *name, WORD type, WORD class)
{
    struct CacheEntry *entry;
    
    for (entry = (struct CacheEntry *)bonami.cache->lh_Head;
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
    LONG now = GetSysTime();
    
    while ((entry = (struct CacheEntry *)bonami.cache->lh_Head)) {
        if (entry->expires <= now) {
            Remove((struct Node *)entry);
            FreeMem(entry, sizeof(struct CacheEntry));
        } else {
            break;
        }
    }
}

/* Resolve hostname */
static LONG resolveHostname(void)
{
    struct hostent *host;
    
    /* Get hostname */
    if (gethostname(bonami.hostname, sizeof(bonami.hostname)) < 0) {
        return BONAMI_ERROR;
    }
    
    /* Resolve hostname */
    host = gethostbyname(bonami.hostname);
    if (!host) {
        return BONAMI_ERROR;
    }
    
    return BONAMI_OK;
}

/* Check service conflict */
static LONG checkServiceConflict(const char *name, const char *type)
{
    struct BonamiServiceNode *service;
    LONG i;
    
    /* Check all interfaces */
    for (i = 0; i < bonami.numInterfaces; i++) {
        if (!bonami.interfaces[i].active) {
            continue;
        }
        
        /* Check services on this interface */
        for (service = (struct BonamiServiceNode *)bonami.interfaces[i].services->lh_Head;
             service->node.ln_Succ;
             service = (struct BonamiServiceNode *)service->node.ln_Succ) {
            if (strcmp(service->service.name, name) == 0 &&
                strcmp(service->service.type, type) == 0) {
                return BONAMI_CONFLICT;
            }
        }
    }
    
    return BONAMI_OK;
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
    if (bonami.logFile < 0) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Store main process */
    bonami.mainProc = (struct Process *)FindTask(NULL);
    
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

/* Write PID file */
static LONG writePIDFile(void)
{
    BPTR file;
    LONG pid;
    
    /* Get process ID */
    pid = GetPID();
    
    /* Write PID file */
    file = Open(PID_FILE, MODE_NEWFILE);
    if (file) {
        FPrintf(file, "%ld\n", pid);
        Close(file);
        return BONAMI_OK;
    }
    
    return BONAMI_ERROR;
}

/* Remove PID file */
static void removePIDFile(void)
{
    DeleteFile(PID_FILE);
}

/* Signal handler */
static void signalHandler(LONG sig)
{
    switch (sig) {
        case SIGTERM:
        case SIGINT:
            logMessage(LOG_INFO, "Received termination signal");
            bonami.running = FALSE;
            break;
            
        case SIGHUP:
            logMessage(LOG_INFO, "Received reload signal");
            loadConfig();
            break;
    }
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
    if (bonami.logFile >= 0) {
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
    if (bonami.logFile >= 0) {
        Close(bonami.logFile);
        bonami.logFile = -1;
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
    
    logMessage(LOG_INFO, "Bonami daemon cleaned up");
}

/* Network monitor task */
static void networkMonitorTask(void)
{
    LONG i;
    
    while (bonami.running) {
        /* Check all interfaces */
        for (i = 0; i < bonami.numInterfaces; i++) {
            checkInterface(&bonami.interfaces[i]);
        }
        
        /* Cleanup cache */
        cleanupCache();
        
        /* Check every second */
        Delay(50);
    }
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
        case BONAMI_MSG_REGISTER:
            /* Validate parameters */
            result = validateServiceName(msg->data.register_msg.service.name);
            if (result != BONAMI_OK) {
                reply->type = result;
                break;
            }
            
            result = validateServiceType(msg->data.register_msg.service.type);
            if (result != BONAMI_OK) {
                reply->type = result;
                break;
            }
            
            if (msg->data.register_msg.service.port == 0) {
                reply->type = BONAMI_BADPORT;
                break;
            }
            
            ObtainSemaphore(&bonami.lock);
            
            /* Check if service exists */
            service = findService(msg->data.register_msg.service.name, 
                                msg->data.register_msg.service.type);
            if (service) {
                /* Update existing service */
                memcpy(&service->service, &msg->data.register_msg.service, 
                       sizeof(struct BonamiService));
                service->lastUpdate = GetSysTime();
                updateServiceRecords(service);
                reply->type = BONAMI_OK;
            } else {
                /* Create new service */
                service = AllocMem(sizeof(struct BonamiServiceNode), MEMF_CLEAR);
                if (service) {
                    memcpy(&service->service, &msg->data.register_msg.service, 
                           sizeof(struct BonamiService));
                    service->lastUpdate = GetSysTime();
                    AddTail(bonami.services, (struct Node *)service);
                    updateServiceRecords(service);
                    reply->type = BONAMI_OK;
                } else {
                    reply->type = BONAMI_NOMEM;
                }
            }
            
            ReleaseSemaphore(&bonami.lock);
            break;
            
        case BONAMI_MSG_UNREGISTER:
            ObtainSemaphore(&bonami.lock);
            
            service = findService(msg->data.unregister_msg.name, 
                                msg->data.unregister_msg.type);
            if (service) {
                removeServiceRecords(service);
                Remove((struct Node *)service);
                FreeMem(service, sizeof(struct BonamiServiceNode));
                reply->type = BONAMI_OK;
            } else {
                reply->type = BONAMI_NOTFOUND;
            }
            
            ReleaseSemaphore(&bonami.lock);
            break;
            
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
            
        case BONAMI_MSG_RESOLVE:
            ObtainSemaphore(&bonami.lock);
            
            service = findService(msg->data.resolve_msg.name, 
                                msg->data.resolve_msg.type);
            if (service) {
                memcpy(msg->data.resolve_msg.result, &service->service, 
                       sizeof(struct BonamiService));
                reply->type = BONAMI_OK;
            } else {
                reply->type = BONAMI_NOTFOUND;
            }
            
            ReleaseSemaphore(&bonami.lock);
            break;
            
        case BONAMI_MSG_QUERY:
            /* Process DNS query */
            result = processDNSQuery(&msg->data.query_msg);
            reply->type = result;
            break;
            
        case BONAMI_MSG_UPDATE:
            ObtainSemaphore(&bonami.lock);
            
            service = findService(msg->data.update_msg.name, 
                                msg->data.update_msg.type);
            if (service) {
                /* Update TXT record */
                if (service->service.txt.data) {
                    FreeMem(service->service.txt.data, service->service.txt.length);
                }
                service->service.txt.data = AllocMem(msg->data.update_msg.txt.length, 
                                                   MEMF_CLEAR);
                if (service->service.txt.data) {
                    memcpy(service->service.txt.data, msg->data.update_msg.txt.data, 
                           msg->data.update_msg.txt.length);
                    service->service.txt.length = msg->data.update_msg.txt.length;
                    updateServiceRecords(service);
                    reply->type = BONAMI_OK;
                } else {
                    reply->type = BONAMI_NOMEM;
                }
            } else {
                reply->type = BONAMI_NOTFOUND;
            }
            
            ReleaseSemaphore(&bonami.lock);
            break;
            
        case BONAMI_MSG_SHUTDOWN:
            bonami.running = FALSE;
            reply->type = BONAMI_OK;
            break;
            
        default:
            reply->type = BONAMI_BADPARAM;
            break;
    }
    
    /* Send reply */
    PutMsg(msg->msg.mn_ReplyPort, (struct Message *)reply);
}

/* Discovery task */
static void discoveryTask(void *arg)
{
    struct BonamiDiscoveryNode *node = (struct BonamiDiscoveryNode *)arg;
    struct sockaddr_in addr;
    UBYTE buffer[512];
    
    /* Create multicast socket */
    node->sock = createMulticastSocket();
    if (node->sock < 0) {
        return;
    }
    
    /* Main discovery loop */
    while (node->running) {
        LONG len = recvfrom(node->sock, buffer, sizeof(buffer), 0, 
                           (struct sockaddr *)&addr, sizeof(addr));
        if (len > 0) {
            /* Process received packet */
            if (buffer[2] & 0x80) {
                processResponse(buffer, len, &addr);
            } else {
                processQuery(buffer, len, &addr);
            }
        }
        
        /* Check for stop signal */
        if (CheckSignal(BONAMI_SIGNAL)) {
            break;
        }
    }
    
    CloseSocket(node->sock);
}

/* Create multicast socket */
static LONG createMulticastSocket(void)
{
    LONG sock;
    struct sockaddr_in addr;
    struct ip_mreq mreq;
    
    /* Create UDP socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    /* Set socket options */
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDR);
    mreq.imr_interface.s_addr = INADDR_ANY;
    
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        CloseSocket(sock);
        return -1;
    }
    
    /* Bind to port */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MDNS_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        CloseSocket(sock);
        return -1;
    }
    
    return sock;
}

/* Process incoming query */
static void processQuery(const UBYTE *data, LONG len, struct sockaddr_in *from)
{
    struct DNSMessage msg;
    struct BonamiServiceNode *service;
    UBYTE response[512];
    LONG responseLen;
    
    /* Parse DNS message */
    if (dnsParseMessage(data, len, &msg) != 0) {
        return;
    }
    
    /* Process each question */
    for (ULONG i = 0; i < msg.numQuestions; i++) {
        struct DNSQuestion *q = &msg.questions[i];
        
        /* Check if it's a service type query */
        if (q->type == DNS_TYPE_PTR && strstr(q->name, "_services._dns-sd._udp.local")) {
            /* Service type enumeration query */
            ObtainSemaphore(&bonami.lock);
            
            /* Create response message */
            struct DNSMessage resp;
            memset(&resp, 0, sizeof(resp));
            resp.id = msg.id;
            resp.flags = DNS_FLAG_RESPONSE | DNS_FLAG_AA;
            resp.numAnswers = 0;
            
            /* Add all service types as answers */
            for (service = (struct BonamiServiceNode *)bonami.services->lh_Head;
                 service->node.ln_Succ;
                 service = (struct BonamiServiceNode *)service->node.ln_Succ) {
                /* Add PTR record for service type */
                struct DNSRecord *r = &resp.answers[resp.numAnswers++];
                r->name = "_services._dns-sd._udp.local";
                r->type = DNS_TYPE_PTR;
                r->class = DNS_CLASS_IN;
                r->ttl = MDNS_TTL;
                r->data = service->service.type;
            }
            
            /* Encode response */
            responseLen = dnsEncodeMessage(&resp, response, sizeof(response));
            if (responseLen > 0) {
                /* Send response */
                sendMulticast(createMulticastSocket(), response, responseLen);
            }
            
            ReleaseSemaphore(&bonami.lock);
        }
        /* Check if it's a service instance query */
        else if (q->type == DNS_TYPE_PTR && strstr(q->name, "._tcp.local")) {
            /* Service instance query */
            ObtainSemaphore(&bonami.lock);
            
            /* Create response message */
            struct DNSMessage resp;
            memset(&resp, 0, sizeof(resp));
            resp.id = msg.id;
            resp.flags = DNS_FLAG_RESPONSE | DNS_FLAG_AA;
            resp.numAnswers = 0;
            
            /* Add matching service instances as answers */
            for (service = (struct BonamiServiceNode *)bonami.services->lh_Head;
                 service->node.ln_Succ;
                 service = (struct BonamiServiceNode *)service->node.ln_Succ) {
                if (strcmp(service->service.type, q->name) == 0) {
                    /* Add PTR record for service instance */
                    struct DNSRecord *r = &resp.answers[resp.numAnswers++];
                    r->name = service->service.type;
                    r->type = DNS_TYPE_PTR;
                    r->class = DNS_CLASS_IN;
                    r->ttl = MDNS_TTL;
                    r->data = service->service.name;
                }
            }
            
            /* Encode response */
            responseLen = dnsEncodeMessage(&resp, response, sizeof(response));
            if (responseLen > 0) {
                /* Send response */
                sendMulticast(createMulticastSocket(), response, responseLen);
            }
            
            ReleaseSemaphore(&bonami.lock);
        }
        /* Check if it's a service info query */
        else if (q->type == DNS_TYPE_SRV || q->type == DNS_TYPE_TXT) {
            /* Service info query */
            ObtainSemaphore(&bonami.lock);
            
            /* Create response message */
            struct DNSMessage resp;
            memset(&resp, 0, sizeof(resp));
            resp.id = msg.id;
            resp.flags = DNS_FLAG_RESPONSE | DNS_FLAG_AA;
            resp.numAnswers = 0;
            
            /* Find matching service */
            service = findService(q->name, NULL);
            if (service) {
                /* Add all records for the service */
                for (ULONG j = 0; j < service->numRecords; j++) {
                    if (service->records[j].type == q->type) {
                        memcpy(&resp.answers[resp.numAnswers++], &service->records[j], 
                               sizeof(struct DNSRecord));
                    }
                }
            }
            
            /* Encode response */
            responseLen = dnsEncodeMessage(&resp, response, sizeof(response));
            if (responseLen > 0) {
                /* Send response */
                sendMulticast(createMulticastSocket(), response, responseLen);
            }
            
            ReleaseSemaphore(&bonami.lock);
        }
    }
}

/* Process incoming response */
static void processResponse(const UBYTE *data, LONG len, struct sockaddr_in *from)
{
    struct DNSMessage msg;
    struct BonamiDiscoveryNode *discovery;
    struct BonamiService service;
    
    /* Parse DNS message */
    if (dnsParseMessage(data, len, &msg) != 0) {
        return;
    }
    
    /* Process each answer */
    for (ULONG i = 0; i < msg.numAnswers; i++) {
        struct DNSRecord *r = &msg.answers[i];
        
        /* Check if it's a service type */
        if (r->type == DNS_TYPE_PTR && strstr(r->name, "_services._dns-sd._udp.local")) {
            /* Found a service type */
            ObtainSemaphore(&bonami.lock);
            
            for (discovery = (struct BonamiDiscoveryNode *)bonami.discoveries->lh_Head;
                 discovery->node.ln_Succ;
                 discovery = (struct BonamiDiscoveryNode *)discovery->node.ln_Succ) {
                if (strcmp(discovery->discovery.type, r->data) == 0) {
                    /* Call discovery callback */
                    discovery->discovery.callback(NULL, discovery->discovery.userData);
                }
            }
            
            ReleaseSemaphore(&bonami.lock);
        }
        /* Check if it's a service instance */
        else if (r->type == DNS_TYPE_PTR && strstr(r->name, "._tcp.local")) {
            /* Found a service instance */
            strncpy(service.name, r->data, sizeof(service.name) - 1);
            strncpy(service.type, r->name, sizeof(service.type) - 1);
            
            /* Look for SRV and TXT records */
            for (ULONG j = 0; j < msg.numAnswers; j++) {
                struct DNSRecord *r2 = &msg.answers[j];
                if (strcmp(r2->name, service.name) == 0) {
                    if (r2->type == DNS_TYPE_SRV) {
                        struct SRVRecord *srv = (struct SRVRecord *)r2->data;
                        service.port = srv->port;
                    } else if (r2->type == DNS_TYPE_TXT) {
                        service.txt.data = r2->data;
                        service.txt.length = strlen(r2->data);
                    }
                }
            }
            
            /* Call discovery callback */
            ObtainSemaphore(&bonami.lock);
            
            for (discovery = (struct BonamiDiscoveryNode *)bonami.discoveries->lh_Head;
                 discovery->node.ln_Succ;
                 discovery = (struct BonamiDiscoveryNode *)discovery->node.ln_Succ) {
                if (strcmp(discovery->discovery.type, service.type) == 0) {
                    discovery->discovery.callback(&service, discovery->discovery.userData);
                }
            }
            
            ReleaseSemaphore(&bonami.lock);
        }
    }
}

/* Send multicast packet */
static void sendMulticast(LONG sock, const UBYTE *data, LONG len)
{
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MDNS_PORT);
    addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDR);
    
    sendto(sock, data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
}

/* Update service DNS records */
static void updateServiceRecords(struct BonamiServiceNode *service)
{
    /* Free existing records */
    if (service->records) {
        FreeMem(service->records, service->numRecords * sizeof(struct DNSRecord));
    }
    
    /* Create new records */
    service->numRecords = 3;  /* PTR, SRV, TXT */
    service->records = AllocMem(service->numRecords * sizeof(struct DNSRecord), 
                               MEMF_CLEAR);
    if (!service->records) {
        return;
    }
    
    /* Create PTR record */
    struct DNSRecord *ptr = &service->records[0];
    ptr->name = service->service.type;
    ptr->type = DNS_TYPE_PTR;
    ptr->class = DNS_CLASS_IN;
    ptr->ttl = MDNS_TTL;
    ptr->data = service->service.name;
    
    /* Create SRV record */
    struct DNSRecord *srv = &service->records[1];
    srv->name = service->service.name;
    srv->type = DNS_TYPE_SRV;
    srv->class = DNS_CLASS_IN;
    srv->ttl = MDNS_TTL;
    
    /* Allocate and set SRV data */
    struct SRVRecord *srvData = AllocMem(sizeof(struct SRVRecord), MEMF_CLEAR);
    if (srvData) {
        srvData->priority = 0;  /* Default priority */
        srvData->weight = 0;    /* Default weight */
        srvData->port = service->service.port;
        gethostname(srvData->target, sizeof(srvData->target));
        srv->data = (char *)srvData;
    }
    
    /* Create TXT record */
    struct DNSRecord *txt = &service->records[2];
    txt->name = service->service.name;
    txt->type = DNS_TYPE_TXT;
    txt->class = DNS_CLASS_IN;
    txt->ttl = MDNS_TTL;
    txt->data = service->service.txt.data;
}

/* Remove service DNS records */
static void removeServiceRecords(struct BonamiServiceNode *service)
{
    if (service->records) {
        FreeMem(service->records, service->numRecords * sizeof(struct DNSRecord));
        service->records = NULL;
        service->numRecords = 0;
    }
}

/* Find a service by name and type */
static struct BonamiServiceNode *findService(const char *name, const char *type)
{
    struct BonamiServiceNode *service;
    
    for (service = (struct BonamiServiceNode *)bonami.services->lh_Head;
         service->node.ln_Succ;
         service = (struct BonamiServiceNode *)service->node.ln_Succ) {
        if (strcmp(service->service.name, name) == 0 && 
            strcmp(service->service.type, type) == 0) {
            return service;
        }
    }
    
    return NULL;
}

/* Find a discovery by type */
static struct BonamiDiscoveryNode *findDiscovery(const char *type)
{
    struct BonamiDiscoveryNode *discovery;
    
    for (discovery = (struct BonamiDiscoveryNode *)bonami.discoveries->lh_Head;
         discovery->node.ln_Succ;
         discovery = (struct BonamiDiscoveryNode *)discovery->node.ln_Succ) {
        if (strcmp(discovery->discovery.type, type) == 0) {
            return discovery;
        }
    }
    
    return NULL;
}

/* Process DNS query */
static LONG processDNSQuery(struct DNSQuery *query)
{
    struct DNSMessage msg;
    UBYTE buffer[512];
    LONG len;
    LONG sock;
    
    /* Create socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return BONAMI_NETWORK;
    }
    
    /* Create query message */
    memset(&msg, 0, sizeof(msg));
    msg.id = GetSysTime() & 0xFFFF;  /* Use system time as ID */
    msg.flags = DNS_FLAG_RD;         /* Request recursion */
    msg.numQuestions = 1;
    
    /* Set up question */
    struct DNSQuestion *q = &msg.questions[0];
    strncpy(q->name, query->name, sizeof(q->name) - 1);
    q->type = query->type;
    q->class = query->class;
    
    /* Encode message */
    len = dnsEncodeMessage(&msg, buffer, sizeof(buffer));
    if (len <= 0) {
        CloseSocket(sock);
        return BONAMI_BADQUERY;
    }
    
    /* Send query */
    if (sendto(sock, buffer, len, 0, (struct sockaddr *)&query->from, 
               sizeof(query->from)) < 0) {
        CloseSocket(sock);
        return BONAMI_NETWORK;
    }
    
    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec = 5;  /* 5 second timeout */
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        CloseSocket(sock);
        return BONAMI_ERROR;
    }
    
    /* Receive response */
    len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
    if (len <= 0) {
        CloseSocket(sock);
        return BONAMI_TIMEOUT;
    }
    
    /* Parse response */
    if (dnsParseMessage(buffer, len, &msg) != 0) {
        CloseSocket(sock);
        return BONAMI_BADRESPONSE;
    }
    
    /* Process answers */
    if (msg.numAnswers > 0) {
        /* Allocate result buffer */
        query->result = AllocMem(msg.numAnswers * sizeof(struct DNSRecord), 
                                MEMF_CLEAR);
        if (!query->result) {
            CloseSocket(sock);
            return BONAMI_NOMEM;
        }
        
        /* Copy answers */
        for (ULONG i = 0; i < msg.numAnswers; i++) {
            memcpy(&query->result[i], &msg.answers[i], sizeof(struct DNSRecord));
        }
        query->resultLen = msg.numAnswers;
    }
    
    CloseSocket(sock);
    return BONAMI_OK;
}

/* Validate service name */
static LONG validateServiceName(const char *name)
{
    if (!name || !name[0]) {
        return BONAMI_BADNAME;
    }
    
    /* Check length */
    if (strlen(name) > 63) {  /* DNS name length limit */
        return BONAMI_BADNAME;
    }
    
    /* Check for invalid characters */
    for (const char *p = name; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') {
            return BONAMI_BADNAME;
        }
    }
    
    return BONAMI_OK;
}

/* Validate service type */
static LONG validateServiceType(const char *type)
{
    if (!type || !type[0]) {
        return BONAMI_BADTYPE;
    }
    
    /* Check format: _service._tcp.local */
    if (type[0] != '_') {
        return BONAMI_BADTYPE;
    }
    
    const char *tcp = strstr(type, "._tcp.local");
    if (!tcp) {
        return BONAMI_BADTYPE;
    }
    
    /* Check service name length */
    if (tcp - type > 15) {  /* Service name length limit */
        return BONAMI_BADTYPE;
    }
    
    return BONAMI_OK;
}

/* Main function */
int main(int argc, char *argv[])
{
    LONG result;
    struct Process *proc;
    
    /* Initialize daemon */
    result = initDaemon();
    if (result != BONAMI_OK) {
        return result;
    }
    
    /* Start network monitor task */
    bonami.networkProc = (struct Process *)CreateNewProcTags(
        NP_Entry, (ULONG)networkMonitorTask,
        NP_Name, (ULONG)"Bonami Monitor",
        NP_Priority, 0,
        NP_StackSize, 4096,
        TAG_DONE
    );
    
    if (!bonami.networkProc) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Start discovery task */
    bonami.discoveryProc = (struct Process *)CreateNewProcTags(
        NP_Entry, (ULONG)discoveryTask,
        NP_Name, (ULONG)"Bonami Discovery",
        NP_Priority, 0,
        NP_StackSize, 4096,
        TAG_DONE
    );
    
    if (!bonami.discoveryProc) {
        cleanupDaemon();
        return BONAMI_ERROR;
    }
    
    /* Main daemon loop */
    while (bonami.running) {
        struct Message *msg;
        
        /* Wait for message */
        msg = WaitPort(bonami.port);
        if (msg) {
            msg = GetMsg(bonami.port);
            if (msg) {
                processMessage((struct BonamiMessage *)msg);
            }
        }
        
        /* Check for break signal */
        if (SetSignal(0, 0) & SIGBREAKF_CTRL_C) {
            bonami.running = FALSE;
        }
    }
    
    /* Cleanup */
    cleanupDaemon();
    return BONAMI_OK;
} 