#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <string.h>
#include <stdio.h>

#include "../include/bonami.h"
#include "../include/dns.h"

/* Library version */
#define LIB_VERSION    1
#define LIB_REVISION   0

/* Message types for daemon communication */
#define BONAMI_MSG_REGISTER    1
#define BONAMI_MSG_UNREGISTER  2
#define BONAMI_MSG_DISCOVER    3
#define BONAMI_MSG_RESOLVE     4
#define BONAMI_MSG_QUERY       5
#define BONAMI_MSG_UPDATE      6

/* Message structure for daemon communication */
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

/* Library base structure - minimal, no state */
struct BonamiBase {
    struct Library lib;
    struct MsgPort *replyPort;
    struct MsgPort *daemonPort;
};

/* Function prototypes */
static LONG sendMessage(struct BonamiBase *base, struct BonamiMessage *msg);
static LONG waitReply(struct BonamiBase *base, struct BonamiMessage *msg);

/* Service registration */
LONG BonamiRegisterService(struct BonamiService *service)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!service || !service->name[0] || !service->type[0]) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_REGISTER;
    memcpy(&msg->data.register_msg.service, service, sizeof(struct BonamiService));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Service unregistration */
LONG BonamiUnregisterService(const char *name, const char *type)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!name || !type) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_UNREGISTER;
    strncpy(msg->data.unregister_msg.name, name, sizeof(msg->data.unregister_msg.name) - 1);
    strncpy(msg->data.unregister_msg.type, type, sizeof(msg->data.unregister_msg.type) - 1);
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Start service discovery */
LONG BonamiStartDiscovery(struct BonamiDiscovery *discovery)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    struct BonamiMessage *msg;
    
    if (!discovery || !discovery->type[0]) {
        return BONAMI_BADPARAM;
    }
    
    /* Allocate message */
    msg = AllocMem(sizeof(struct BonamiMessage), MEMF_CLEAR);
    if (!msg) {
        return BONAMI_NOMEM;
    }
    
    /* Set up message */
    msg->type = BONAMI_MSG_DISCOVER;
    memcpy(&msg->data.discover_msg.discovery, discovery, sizeof(struct BonamiDiscovery));
    
    /* Send to daemon */
    LONG result = sendMessage(base, msg);
    FreeMem(msg, sizeof(struct BonamiMessage));
    
    return result;
}

/* Stop service discovery */
LONG BonamiStopDiscovery(struct BonamiDiscovery *discovery)
{
    /* This is handled by the daemon when the client disconnects */
    return BONAMI_OK;
}

/* Send message to daemon */
static LONG sendMessage(struct BonamiBase *base, struct BonamiMessage *msg)
{
    /* Set up message */
    msg->msg.mn_Node.ln_Type = NT_MESSAGE;
    msg->msg.mn_ReplyPort = base->replyPort;
    msg->msg.mn_Length = sizeof(struct BonamiMessage);
    
    /* Send to daemon */
    PutMsg(base->daemonPort, (struct Message *)msg);
    
    /* Wait for reply */
    return waitReply(base, msg);
}

/* Wait for reply from daemon */
static LONG waitReply(struct BonamiBase *base, struct BonamiMessage *msg)
{
    struct Message *reply;
    
    /* Wait for reply */
    reply = WaitPort(base->replyPort);
    if (!reply) {
        return BONAMI_ERROR;
    }
    
    /* Get reply */
    reply = GetMsg(base->replyPort);
    if (!reply) {
        return BONAMI_ERROR;
    }
    
    /* Check result */
    LONG result = ((struct BonamiMessage *)reply)->type;
    FreeMem(reply, sizeof(struct BonamiMessage));
    
    return result;
}

/* Library open */
struct Library *OpenLibrary(void)
{
    struct BonamiBase *base = (struct BonamiBase *)AllocMem(sizeof(struct BonamiBase), MEMF_CLEAR);
    if (!base) {
        return NULL;
    }
    
    /* Initialize library */
    base->lib.lib_Node.ln_Type = NT_LIBRARY;
    base->lib.lib_Node.ln_Name = "bonami.library";
    base->lib.lib_Flags = LIBF_SUMUSED | LIBF_CHANGED;
    base->lib.lib_Version = LIB_VERSION;
    base->lib.lib_Revision = LIB_REVISION;
    base->lib.lib_IdString = "BonAmi mDNS Library";
    
    /* Create reply port */
    base->replyPort = CreateMsgPort();
    if (!base->replyPort) {
        FreeMem(base, sizeof(struct BonamiBase));
        return NULL;
    }
    
    /* Find daemon port */
    base->daemonPort = FindPort("BONAMI_DAEMON");
    if (!base->daemonPort) {
        DeleteMsgPort(base->replyPort);
        FreeMem(base, sizeof(struct BonamiBase));
        return NULL;
    }
    
    return (struct Library *)base;
}

/* Library close */
void CloseLibrary(void)
{
    struct BonamiBase *base = (struct BonamiBase *)SysBase->LibNode;
    
    if (base->replyPort) {
        DeleteMsgPort(base->replyPort);
    }
    
    FreeMem(base, sizeof(struct BonamiBase));
}

/* Library expunge */
void ExpungeLibrary(void)
{
    /* Nothing to do here */
} 