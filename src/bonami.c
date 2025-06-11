#include <exec/types.h>
#include <exec/memory.h>
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

/* Message types */
#define BONAMI_MSG_REGISTER    1
#define BONAMI_MSG_UNREGISTER  2
#define BONAMI_MSG_DISCOVER    3
#define BONAMI_MSG_RESOLVE     4
#define BONAMI_MSG_QUERY       5
#define BONAMI_MSG_UPDATE      6
#define BONAMI_MSG_SHUTDOWN    7

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
};

/* Discovery node structure */
struct BonamiDiscoveryNode {
    struct Node node;
    struct BonamiDiscovery discovery;
    struct Task *task;
    BOOL running;
};

/* Global state */
struct {
    struct SignalSemaphore lock;
    struct MsgPort *port;
    struct List *services;
    struct List *discoveries;
    struct Task *mainTask;
    struct Task *networkTask;
    BOOL running;
    BOOL networkReady;
} bonami;

/* Function prototypes */
static void initDaemon(void);
static void cleanupDaemon(void);
static void processMessage(struct BonamiMessage *msg);
static void networkMonitorTask(void);
static struct BonamiServiceNode *findService(const char *name, const char *type);
static struct BonamiDiscoveryNode *findDiscovery(const char *type);
static void discoveryTask(void *arg);
static LONG checkNetworkStatus(void);

/* Initialize daemon */
static void initDaemon(void)
{
    /* Initialize semaphore */
    InitSemaphore(&bonami.lock);
    
    /* Create message port */
    bonami.port = CreateMsgPort();
    if (!bonami.port) {
        return;
    }
    
    /* Initialize lists */
    bonami.services = AllocMem(sizeof(struct List), MEMF_CLEAR);
    bonami.discoveries = AllocMem(sizeof(struct List), MEMF_CLEAR);
    
    if (bonami.services && bonami.discoveries) {
        NewList(bonami.services);
        NewList(bonami.discoveries);
    }
    
    /* Set main task */
    bonami.mainTask = FindTask(NULL);
    bonami.running = TRUE;
    bonami.networkReady = FALSE;
    
    /* Start network monitor task */
    bonami.networkTask = CreateTask("BonAmi Network", 0, networkMonitorTask, NULL, 4096);
}

/* Cleanup daemon */
static void cleanupDaemon(void)
{
    if (bonami.services) {
        /* Free all service nodes */
        struct Node *node, *next;
        for (node = bonami.services->lh_Head; (next = node->ln_Succ); node = next) {
            Remove(node);
            FreeMem(node, sizeof(struct BonamiServiceNode));
        }
        FreeMem(bonami.services, sizeof(struct List));
    }
    
    if (bonami.discoveries) {
        /* Stop all discoveries */
        struct Node *node, *next;
        for (node = bonami.discoveries->lh_Head; (next = node->ln_Succ); node = next) {
            struct BonamiDiscoveryNode *discovery = (struct BonamiDiscoveryNode *)node;
            discovery->running = FALSE;
            Signal(discovery->task, SIGBREAKF_CTRL_C);
        }
        FreeMem(bonami.discoveries, sizeof(struct List));
    }
    
    if (bonami.port) {
        DeleteMsgPort(bonami.port);
    }
}

/* Network monitor task */
static void networkMonitorTask(void)
{
    LONG lastStatus = -1;
    
    while (bonami.running) {
        LONG status = checkNetworkStatus();
        
        if (status != lastStatus) {
            ObtainSemaphore(&bonami.lock);
            
            if (status) {
                /* Network is up */
                if (!bonami.networkReady) {
                    bonami.networkReady = TRUE;
                    /* TODO: Start mDNS services */
                }
            } else {
                /* Network is down */
                if (bonami.networkReady) {
                    bonami.networkReady = FALSE;
                    /* TODO: Stop mDNS services */
                }
            }
            
            ReleaseSemaphore(&bonami.lock);
            lastStatus = status;
        }
        
        /* Check every second */
        Delay(50);
    }
}

/* Check network status */
static LONG checkNetworkStatus(void)
{
    struct ifreq ifr;
    LONG sock;
    
    /* Create socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    /* Get first interface */
    ifr.ifr_name[0] = '\0';
    if (ioctl(sock, SIOCGIFNAME, &ifr) < 0) {
        CloseSocket(sock);
        return 0;
    }
    
    /* Check interface status */
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        CloseSocket(sock);
        return 0;
    }
    
    CloseSocket(sock);
    
    /* Check if interface is up */
    return (ifr.ifr_flags & IFF_UP) ? 1 : 0;
}

/* Main daemon loop */
int main(void)
{
    struct Message *msg;
    
    /* Initialize daemon */
    initDaemon();
    
    /* Main message loop */
    while (bonami.running) {
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