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

/* SRV record data structure */
struct SRVRecord {
    UWORD priority;
    UWORD weight;
    UWORD port;
    char target[256];
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
static LONG processDNSQuery(struct DNSQuery *query);
static LONG validateServiceName(const char *name);
static LONG validateServiceType(const char *type);

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
    LONG retryCount = 0;
    
    while (bonami.running) {
        LONG status = checkNetworkStatus();
        
        if (status != lastStatus) {
            ObtainSemaphore(&bonami.lock);
            
            if (status) {
                /* Network is up */
                if (!bonami.networkReady) {
                    /* Try to create multicast socket */
                    LONG sock = createMulticastSocket();
                    if (sock >= 0) {
                        CloseSocket(sock);
                        bonami.networkReady = TRUE;
                        retryCount = 0;
                    } else {
                        /* Network might not be fully ready */
                        if (++retryCount >= 5) {  /* Try 5 times */
                            bonami.networkReady = TRUE;
                            retryCount = 0;
                        }
                    }
                }
            } else {
                /* Network is down */
                if (bonami.networkReady) {
                    bonami.networkReady = FALSE;
                    retryCount = 0;
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