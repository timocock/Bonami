#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/commodities.h>
#include <libraries/commodities.h>
#include <string.h>
#include <stdio.h>

#include "../include/bonami.h"

/* Constants */
#define MDNS_PORT 5353
#define MDNS_MULTICAST_ADDR 0xE00000FB  /* 224.0.0.251 in network byte order */
#define MDNS_TTL 255
#define BONAMID_SIGNAL SIGBREAKF_CTRL_C

/* Global variables */
static struct Task *mainTask;
static struct MsgPort *replyPort;
static struct SignalSemaphore lock;
static BOOL running = FALSE;
static struct Library *CommoditiesBase;
static struct CxObj *cxObj;
static struct MsgPort *cxPort;

/* Function prototypes */
static void init(void);
static void cleanup(void);
static void handleMulticast(void);
static LONG createMulticastSocket(void);
static void processQuery(const UBYTE *data, LONG len, struct sockaddr_in *from);
static void processResponse(const UBYTE *data, LONG len, struct sockaddr_in *from);
static void setupCommodity(void);
static void removeCommodity(void);

/* Main entry point */
int main(void)
{
    /* Open commodities library */
    CommoditiesBase = OpenLibrary("commodities.library", 0);
    if (!CommoditiesBase) {
        Printf("Failed to open commodities.library\n");
        return 1;
    }

    init();
    setupCommodity();
    
    /* Main loop */
    while (running) {
        ULONG signals = Wait(BONAMID_SIGNAL | SIGBREAKF_CTRL_C);
        
        if (signals & BONAMID_SIGNAL) {
            running = FALSE;
        } else {
            handleMulticast();
        }
    }
    
    removeCommodity();
    cleanup();
    CloseLibrary(CommoditiesBase);
    return 0;
}

/* Initialize the daemon */
static void init(void)
{
    /* Initialize semaphore */
    InitSemaphore(&lock);
    
    /* Create reply port */
    replyPort = CreateMsgPort();
    if (!replyPort) {
        Printf("Failed to create reply port\n");
        return;
    }
    
    /* Create main task */
    mainTask = FindTask(NULL);
    
    running = TRUE;
}

/* Cleanup resources */
static void cleanup(void)
{
    if (replyPort) {
        DeleteMsgPort(replyPort);
    }
}

/* Setup commodity */
static void setupCommodity(void)
{
    cxPort = CreateMsgPort();
    if (!cxPort) {
        Printf("Failed to create commodity port\n");
        return;
    }

    /* Create commodity object */
    cxObj = CxBroker(NULL, 0);
    if (!cxObj) {
        Printf("Failed to create commodity broker\n");
        return;
    }

    /* Set up commodity */
    CxObjType(cxObj) = CX_COMMAND;
    CxObjData(cxObj) = CXCMD_DISABLE;
    CxObjError(cxObj) = 0;
    CxObjCustom(cxObj) = NULL;

    /* Attach to input event stream */
    if (!AttachCxObj(cxObj, cxPort)) {
        Printf("Failed to attach commodity\n");
        return;
    }

    /* Activate commodity */
    ActivateCxObj(cxObj, TRUE);
}

/* Remove commodity */
static void removeCommodity(void)
{
    if (cxObj) {
        DeleteCxObj(cxObj);
    }
    if (cxPort) {
        DeleteMsgPort(cxPort);
    }
}

/* Handle multicast communication */
static void handleMulticast(void)
{
    static struct sockaddr_in addr;
    static UBYTE buffer[512];
    LONG len;
    LONG sock;
    
    /* Create multicast socket */
    sock = createMulticastSocket();
    if (sock < 0) {
        return;
    }
    
    /* Receive data */
    len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, sizeof(addr));
    if (len > 0) {
        /* Check if it's a query or response */
        if (buffer[2] & 0x80) {
            processResponse(buffer, len, &addr);
        } else {
            processQuery(buffer, len, &addr);
        }
    }
    
    /* Close socket */
    CloseSocket(sock);
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
    /* TODO: Implement query processing */
}

/* Process incoming response */
static void processResponse(const UBYTE *data, LONG len, struct sockaddr_in *from)
{
    /* TODO: Implement response processing */
} 