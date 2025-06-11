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

/* Constants */
#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR 0xE00000FB  /* 224.0.0.251 in network byte order */
#define MDNS_TTL 255
#define BONAMI_SIGNAL SIGBREAKF_CTRL_C

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
static LONG createMulticastSocket(void);
static void processQuery(const UBYTE *data, LONG len, struct sockaddr_in *from);
static void processResponse(const UBYTE *data, LONG len, struct sockaddr_in *from);
static void sendMulticast(LONG sock, const UBYTE *data, LONG len);
static void updateServiceRecords(struct BonamiServiceNode *service);
static void removeServiceRecords(struct BonamiServiceNode *service);

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

/* Process incoming message */
static void processMessage(struct BonamiMessage *msg)
{
    struct BonamiMessage *reply;
    struct BonamiServiceNode *service;
    struct BonamiDiscoveryNode *discovery;
    
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
            /* TODO: Implement DNS query */
            reply->type = BONAMI_ERROR;
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
    mreq.imr_multiaddr.s_addr = MDNS_MULTICAST_ADDR;
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
            /* TODO: Send list of service types */
        }
        /* Check if it's a service instance query */
        else if (q->type == DNS_TYPE_PTR && strstr(q->name, "._tcp.local")) {
            /* Service instance query */
            /* TODO: Send matching service instances */
        }
        /* Check if it's a service info query */
        else if (q->type == DNS_TYPE_SRV || q->type == DNS_TYPE_TXT) {
            /* Service info query */
            ObtainSemaphore(&bonami.lock);
            
            for (service = (struct BonamiServiceNode *)bonami.services->lh_Head;
                 service->node.ln_Succ;
                 service = (struct BonamiServiceNode *)service->node.ln_Succ) {
                /* TODO: Check if service matches query and send response */
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
            /* TODO: Process service instance */
        }
        /* Check if it's service info */
        else if (r->type == DNS_TYPE_SRV || r->type == DNS_TYPE_TXT) {
            /* Found service info */
            /* TODO: Process service info */
        }
    }
}

/* Send multicast packet */
static void sendMulticast(LONG sock, const UBYTE *data, LONG len)
{
    struct sockaddr_in addr;
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MDNS_PORT);
    addr.sin_addr.s_addr = MDNS_MULTICAST_ADDR;
    
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
    /* TODO: Set SRV data (priority, weight, port, target) */
    
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