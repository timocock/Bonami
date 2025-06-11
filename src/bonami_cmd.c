#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <exec/semaphores.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

#include "bonami.h"

/* Version string */
static const char version[] = "$VER: bactl 40.0 (01.01.2024)";

/* Memory pool sizes */
#define POOL_PUDDLE_SIZE   4096
#define POOL_THRESHOLD     128
#define POOL_MAX_PUDDLES   16

/* Command structure */
struct Command {
    const char *name;
    const char *template;
    const char *description;
    LONG (*handler)(struct RDArgs *args);
};

/* Global state */
static struct {
    struct Library *BonAmiBase;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
    BOOL debug;
} cmd;

/* Forward declarations */
static void printUsage(const struct Command *cmd);
static void printHelp(void);
static LONG handleDiscover(struct RDArgs *args);
static LONG handleRegister(struct RDArgs *args);
static LONG handleUnregister(struct RDArgs *args);
static LONG handleList(struct RDArgs *args);
static LONG handleResolve(struct RDArgs *args);
static LONG handleMonitor(struct RDArgs *args);
static LONG handleStatus(struct RDArgs *args);
static void handleSignals(void);

/* Command table */
static const struct Command commands[] = {
    {
        "discover",
        "TYPE/K,NAME/K,FILTER/K,TIMEOUT/N",
        "Discover services of a specific type",
        handleDiscover
    },
    {
        "register",
        "NAME/K,TYPE/K,PORT/N,TXT/M",
        "Register a new service",
        handleRegister
    },
    {
        "unregister",
        "NAME/K,TYPE/K",
        "Unregister a service",
        handleUnregister
    },
    {
        "list",
        "TYPE/K",
        "List all services of a specific type",
        handleList
    },
    {
        "resolve",
        "NAME/K,TYPE/K",
        "Resolve a service to its address and port",
        handleResolve
    },
    {
        "monitor",
        "NAME/K,TYPE/K,INTERVAL/N,NOTIFY/S",
        "Monitor a service for changes",
        handleMonitor
    },
    {
        "status",
        "",
        "Show daemon status",
        handleStatus
    },
    { NULL, NULL, NULL, NULL }
};

/* Print usage for a command */
static void printUsage(const struct Command *cmd) {
    printf("Usage: bactl %s\n", cmd->template);
}

/* Print help text */
static void printHelp(void) {
    printf("BonAmi mDNS Control Utility (bactl)\n\n");
    printf("Usage: bactl <command> [options]\n\n");
    printf("Commands:\n");
    for (const struct Command *cmd = commands; cmd->name; cmd++) {
        printf("  %-10s %s\n", cmd->name, cmd->description);
    }
    printf("\nUse 'bactl <command>' for more information about a command.\n");
}

/* Initialize command tool */
static LONG initCommand(void)
{
    /* Initialize state */
    cmd.debug = FALSE;
    
    /* Open library */
    #ifdef __amigaos4__
    cmd.BonAmiBase = IExec->OpenLibrary("bonami.library", 40);
    if (!cmd.BonAmiBase) {
        return RETURN_ERROR;
    }
    
    cmd.IBonAmi = (struct BonAmiIFace *)IExec->GetInterface(cmd.BonAmiBase, "main", 1, NULL);
    if (!cmd.IBonAmi) {
        IExec->CloseLibrary(cmd.BonAmiBase);
        return RETURN_ERROR;
    }
    #else
    cmd.BonAmiBase = OpenLibrary("bonami.library", 40);
    if (!cmd.BonAmiBase) {
        return RETURN_ERROR;
    }
    #endif
    
    return RETURN_OK;
}

/* Cleanup command tool */
static void cleanupCommand(void)
{
    #ifdef __amigaos4__
    /* Drop interface */
    if (cmd.IBonAmi) {
        IExec->DropInterface((struct Interface *)cmd.IBonAmi);
        cmd.IBonAmi = NULL;
    }
    #endif
    
    /* Close library */
    if (cmd.BonAmiBase) {
        CloseLibrary(cmd.BonAmiBase);
        cmd.BonAmiBase = NULL;
    }
}

/* Discovery callback */
static void discoveryCallback(struct BAService *service, APTR userData)
{
    printf("Found service: %s\n", service->name);
    printf("  Type: %s\n", service->type);
    printf("  Port: %d\n", service->port);
    printf("  Host: %s\n", service->host);
    
    if (service->txt) {
        printf("  TXT: %s\n", service->txt);
    }
    printf("\n");
}

/* Handle discover command */
static LONG handleDiscover(struct RDArgs *args)
{
    struct BADiscovery discovery;
    LONG result;
    
    /* Check arguments */
    if (!(args->RDA_Flags & RDA_TYPE)) {
        printf("Error: TYPE argument is required\n");
        printUsage(&commands[0]);
        return RETURN_ERROR;
    }
    
    /* Start discovery */
    discovery.type = (char *)args->RDA_TYPE;
    discovery.callback = discoveryCallback;
    discovery.userData = NULL;
    
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStartDiscovery(&discovery);
    #else
    result = BAStartDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to start discovery\n");
        return RETURN_ERROR;
    }
    
    /* Wait for discovery to complete */
    Delay(50);
    
    /* Stop discovery */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStopDiscovery(&discovery);
    #else
    result = BAStopDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to stop discovery\n");
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Handle register command */
static LONG handleRegister(struct RDArgs *args)
{
    struct BAService service;
    LONG result;
    
    /* Get arguments */
    if (!(args->RDA_Flags & RDA_NAME) || !(args->RDA_Flags & RDA_TYPE) || !(args->RDA_Flags & RDA_PORT)) {
        printf("Error: NAME, TYPE, and PORT arguments are required\n");
        printUsage(&commands[1]);
        return RETURN_ERROR;
    }
    
    /* Initialize service */
    service.name = (char *)args->RDA_NAME;
    service.type = (char *)args->RDA_TYPE;
    service.port = *(LONG *)args->RDA_PORT;
    service.txt = NULL;
    
    /* Add TXT record if specified */
    if (args->RDA_Flags & RDA_TXT) {
        service.txt = (char *)args->RDA_TXT;
    }
    
    /* Register service */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BARegisterService(&service);
    #else
    result = BARegisterService(&service);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to register service\n");
        return RETURN_ERROR;
    }
    
    printf("Service registered successfully\n");
    return RETURN_OK;
}

/* Handle unregister command */
static LONG handleUnregister(struct RDArgs *args)
{
    LONG result;
    
    /* Get arguments */
    if (!(args->RDA_Flags & RDA_NAME) || !(args->RDA_Flags & RDA_TYPE)) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[2]);
        return RETURN_ERROR;
    }
    
    /* Unregister service */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAUnregisterService((char *)args->RDA_NAME, (char *)args->RDA_TYPE);
    #else
    result = BAUnregisterService((char *)args->RDA_NAME, (char *)args->RDA_TYPE);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to unregister service\n");
        return RETURN_ERROR;
    }
    
    printf("Service unregistered successfully\n");
    return RETURN_OK;
}

/* Handle list command */
static LONG handleList(struct RDArgs *args)
{
    struct BADiscovery discovery;
    LONG result;
    
    /* Get arguments */
    if (!(args->RDA_Flags & RDA_TYPE)) {
        printf("Error: TYPE argument is required\n");
        printUsage(&commands[3]);
        return RETURN_ERROR;
    }
    
    /* Start discovery */
    discovery.type = (char *)args->RDA_TYPE;
    discovery.callback = discoveryCallback;
    discovery.userData = NULL;
    
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStartDiscovery(&discovery);
    #else
    result = BAStartDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to start discovery\n");
        return RETURN_ERROR;
    }
    
    /* Wait for discovery to complete */
    Delay(50);
    
    /* Stop discovery */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStopDiscovery(&discovery);
    #else
    result = BAStopDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to stop discovery\n");
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Handle resolve command */
static LONG handleResolve(struct RDArgs *args)
{
    struct BAService service;
    LONG result;
    
    /* Get arguments */
    if (!(args->RDA_Flags & RDA_NAME) || !(args->RDA_Flags & RDA_TYPE)) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[4]);
        return RETURN_ERROR;
    }
    
    /* Initialize service */
    service.name = (char *)args->RDA_NAME;
    service.type = (char *)args->RDA_TYPE;
    
    /* Start discovery */
    struct BADiscovery discovery = {
        .type = service.type,
        .callback = discoveryCallback,
        .userData = NULL
    };
    
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStartDiscovery(&discovery);
    #else
    result = BAStartDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to start discovery\n");
        return RETURN_ERROR;
    }
    
    /* Wait for discovery to complete */
    Delay(50);
    
    /* Stop discovery */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStopDiscovery(&discovery);
    #else
    result = BAStopDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to stop discovery\n");
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Handle monitor command */
static LONG handleMonitor(struct RDArgs *args)
{
    LONG result;
    
    /* Get arguments */
    if (!(args->RDA_Flags & RDA_NAME) || !(args->RDA_Flags & RDA_TYPE)) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[5]);
        return RETURN_ERROR;
    }
    
    /* Get interval */
    LONG interval = 30;
    if (args->RDA_Flags & RDA_INTERVAL) {
        interval = *(LONG *)args->RDA_INTERVAL;
    }
    
    /* Get notify flag */
    BOOL notify = FALSE;
    if (args->RDA_Flags & RDA_NOTIFY) {
        notify = TRUE;
    }
    
    /* Start monitoring */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAMonitorService((char *)args->RDA_NAME, (char *)args->RDA_TYPE, interval, notify);
    #else
    result = BAMonitorService((char *)args->RDA_NAME, (char *)args->RDA_TYPE, interval, notify);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to start monitoring\n");
        return RETURN_ERROR;
    }
    
    printf("Monitoring service %s of type %s\n", (char *)args->RDA_NAME, (char *)args->RDA_TYPE);
    printf("Press Ctrl-C to stop\n");
    
    /* Set up signal handling */
    SetSignal(0, SIGBREAKF_CTRL_C);
    
    /* Wait for Ctrl-C */
    while (1) {
        if (SetSignal(0, 0) & SIGBREAKF_CTRL_C) {
            break;
        }
        Delay(50);
    }
    
    return RETURN_OK;
}

/* Handle status command */
static LONG handleStatus(struct RDArgs *args)
{
    struct BAStatus status;
    struct BAInterface interface;
    LONG result;
    
    /* Get daemon status */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAGetDaemonStatus(&status);
    #else
    result = BAGetDaemonStatus(&status);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to get daemon status\n");
        return RETURN_ERROR;
    }
    
    /* Print status */
    printf("BonAmi mDNS Daemon Status\n\n");
    printf("Library Version: 40.0\n");
    printf("Status: Running\n\n");
    printf("Services: %d\n", status.numServices);
    printf("Discoveries: %d\n", status.numDiscoveries);
    printf("Monitors: %d\n", status.numMonitors);
    printf("Interfaces: %d\n", status.numInterfaces);
    
    /* Print interface status */
    printf("\nInterfaces:\n");
    for (struct InterfaceNode *iface = (struct InterfaceNode *)daemonState.interfaces.lh_Head;
         iface->node.ln_Succ;
         iface = (struct InterfaceNode *)iface->node.ln_Succ) {
        interface.name = iface->name;
        #ifdef __amigaos4__
        result = cmd.IBonAmi->BAGetInterfaceStatus(&interface);
        #else
        result = BAGetInterfaceStatus(&interface);
        #endif
        if (result == BA_OK) {
            printf("  %s: %s (%s)\n", interface.name,
                   inet_ntoa(interface.addr),
                   interface.up ? "up" : "down");
        }
    }
    
    return RETURN_OK;
}

/* Handle signals */
static void handleSignals(void)
{
    ULONG signals = SetSignal(0, 0);
    if (signals & SIGBREAKF_CTRL_C) {
        /* Graceful exit */
        cleanupCommand();
        exit(RETURN_OK);
    } else if (signals & SIGBREAKF_CTRL_D) {
        /* Toggle debug output */
        cmd.debug = !cmd.debug;
        printf("Debug output %s\n", cmd.debug ? "enabled" : "disabled");
    } else if (signals & SIGBREAKF_CTRL_E) {
        /* Emergency exit */
        cleanupCommand();
        exit(RETURN_ERROR);
    }
}

/* Main function */
int main(int argc, char **argv)
{
    struct RDArgs *args;
    const struct Command *cmd;
    LONG result = RETURN_OK;
    
    /* Initialize command tool */
    if (initCommand() != RETURN_OK) {
        printf("Error: Failed to initialize command tool\n");
        return RETURN_ERROR;
    }
    
    /* Set up signal handling */
    SetSignal(0, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E);
    
    /* Check arguments */
    if (argc < 2) {
        printHelp();
        cleanupCommand();
        return RETURN_OK;
    }
    
    /* Find command */
    for (cmd = commands; cmd->name; cmd++) {
        if (strcmp(cmd->name, argv[1]) == 0) {
            break;
        }
    }
    
    if (!cmd->name) {
        printf("Error: Unknown command '%s'\n", argv[1]);
        printHelp();
        cleanupCommand();
        return RETURN_ERROR;
    }
    
    /* Parse arguments */
    args = ReadArgs(cmd->template, argv + 2, NULL);
    if (!args) {
        if (IoErr() == ERROR_REQUIRED_ARG_MISSING) {
            printUsage(cmd);
        } else {
            printf("Error: Invalid arguments\n");
        }
        cleanupCommand();
        return RETURN_ERROR;
    }
    
    /* Execute command */
    result = cmd->handler(args);
    
    /* Cleanup */
    FreeArgs(args);
    cleanupCommand();
    return result;
} 