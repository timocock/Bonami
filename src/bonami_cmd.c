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
    APTR memPool;     /* Memory pool for allocations */
    struct Task *mainTask;
    BOOL debug;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
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
static LONG handleConfig(struct RDArgs *args);
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
        "config",
        "SET/M",
        "Configure the daemon",
        handleConfig
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
    /* Create memory pool */
    cmd.memPool = CreatePool(MEMF_ANY, POOL_PUDDLE_SIZE, POOL_THRESHOLD);
    if (!cmd.memPool) {
        return RETURN_ERROR;
    }
    
    /* Initialize state */
    cmd.debug = FALSE;
    cmd.mainTask = FindTask(NULL);
    
    #ifdef __amigaos4__
    /* Get BonAmi interface */
    struct Library *bonamiBase = OpenLibrary("bonami.library", 40);
    if (!bonamiBase) {
        DeletePool(cmd.memPool);
        return RETURN_ERROR;
    }
    
    cmd.IBonAmi = (struct BonAmiIFace *)GetInterface(bonamiBase, "main", 1, NULL);
    if (!cmd.IBonAmi) {
        CloseLibrary(bonamiBase);
        DeletePool(cmd.memPool);
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
        struct Library *bonamiBase = cmd.IBonAmi->Data.LibBase;
        DropInterface((struct Interface *)cmd.IBonAmi);
        CloseLibrary(bonamiBase);
        cmd.IBonAmi = NULL;
    }
    #endif
    
    /* Delete memory pool */
    if (cmd.memPool) {
        DeletePool(cmd.memPool);
        cmd.memPool = NULL;
    }
}

/* Allocate from pool */
static APTR AllocPooled(ULONG size)
{
    if (!cmd.memPool) return NULL;
    return AllocPooled(cmd.memPool, size);
}

/* Free from pool */
static void FreePooled(APTR memory, ULONG size)
{
    if (!cmd.memPool || !memory) return;
    FreePooled(cmd.memPool, memory, size);
}

/* Handle discover command */
static LONG handleDiscover(struct RDArgs *args)
{
    struct BAConfig config;
    struct BATXTRecord *txt = NULL;
    struct BAServiceList *services = NULL;
    LONG result;
    
    /* Check arguments */
    if (args->RDA_Flags & RDA_TYPE) {
        #ifdef __amigaos4__
        txt = cmd.IBonAmi->BACreateTXTRecord();
        #else
        txt = BACreateTXTRecord();
        #endif
        if (!txt) {
            printf("Error: Failed to create TXT record\n");
            return RETURN_ERROR;
        }
        
        /* Add TXT record */
        #ifdef __amigaos4__
        result = cmd.IBonAmi->BAAddTXTRecord(txt, (char *)args->RDA_TYPE, (char *)args->RDA_NAME);
        #else
        result = BAAddTXTRecord(txt, (char *)args->RDA_TYPE, (char *)args->RDA_NAME);
        #endif
        if (result != BA_OK) {
            printf("Error: Failed to add TXT record\n");
            #ifdef __amigaos4__
            cmd.IBonAmi->BAFreeTXTRecord(txt);
            #else
            BAFreeTXTRecord(txt);
            #endif
            return RETURN_ERROR;
        }
    }
    
    /* Start discovery */
    #ifdef __amigaos4__
    result = cmd.IBonAmi->BAStartDiscovery((char *)args->RDA_TYPE, txt);
    #else
    result = BAStartDiscovery((char *)args->RDA_TYPE, txt);
    #endif
    if (result != BA_OK) {
        printf("Error: Failed to start discovery\n");
        if (txt) {
            #ifdef __amigaos4__
            cmd.IBonAmi->BAFreeTXTRecord(txt);
            #else
            BAFreeTXTRecord(txt);
            #endif
        }
        return RETURN_ERROR;
    }
    
    /* Wait for discovery to complete */
    Delay(50);
    
    /* Get services */
    #ifdef __amigaos4__
    services = cmd.IBonAmi->BAGetServices((char *)args->RDA_TYPE);
    #else
    services = BAGetServices((char *)args->RDA_TYPE);
    #endif
    if (!services) {
        printf("Error: Failed to get services\n");
        #ifdef __amigaos4__
        cmd.IBonAmi->BAStopDiscovery((char *)args->RDA_TYPE);
        #else
        BAStopDiscovery((char *)args->RDA_TYPE);
        #endif
        if (txt) {
            #ifdef __amigaos4__
            cmd.IBonAmi->BAFreeTXTRecord(txt);
            #else
            BAFreeTXTRecord(txt);
            #endif
        }
        return RETURN_ERROR;
    }
    
    /* Print services */
    struct BAServiceList *current;
    for (current = services; current; current = current->next) {
        printf("Service: %s\n", current->name);
        printf("  Type: %s\n", current->type);
        printf("  Port: %d\n", current->port);
        printf("  Host: %s\n", current->host);
        
        /* Print TXT records */
        struct BATXTRecord *txt;
        for (txt = current->txt; txt; txt = txt->next) {
            printf("  %s=%s\n", txt->key, txt->value);
        }
    }
    
    /* Cleanup */
    #ifdef __amigaos4__
    cmd.IBonAmi->BAFreeServiceList(services);
    cmd.IBonAmi->BAStopDiscovery((char *)args->RDA_TYPE);
    if (txt) {
        cmd.IBonAmi->BAFreeTXTRecord(txt);
    }
    #else
    BAFreeServiceList(services);
    BAStopDiscovery((char *)args->RDA_TYPE);
    if (txt) {
        BAFreeTXTRecord(txt);
    }
    #endif
    
    return RETURN_OK;
}

/* Handle register command */
static LONG handleRegister(struct RDArgs *args)
{
    struct BAConfig config;
    struct BATXTRecord *txt = NULL;
    char *name = NULL;
    char *type = NULL;
    LONG port = 0;
    char **txtArgs = NULL;
    LONG numTxtArgs = 0;

    /* Get arguments */
    if (args->RDA_Flags & RDA_NAME) {
        name = (char *)args->RDA_NAME;
    }
    if (args->RDA_Flags & RDA_TYPE) {
        type = (char *)args->RDA_TYPE;
    }
    if (args->RDA_Flags & RDA_PORT) {
        port = *(LONG *)args->RDA_PORT;
    }
    if (args->RDA_Flags & RDA_TXT) {
        txtArgs = (char **)args->RDA_TXT;
        numTxtArgs = args->RDA_TXT_Count;
    }

    /* Check required arguments */
    if (!name || !type || !port) {
        printf("Error: NAME, TYPE, and PORT arguments are required\n");
        printUsage(&commands[1]);
        return RETURN_ERROR;
    }

    /* Initialize library */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAOpenLibrary() != BA_OK) {
    #else
    if (BAOpenLibrary() != BA_OK) {
    #endif
        printf("Error: Failed to open library\n");
        return RETURN_ERROR;
    }
    
    /* Get current config */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAGetConfig(&config) != BA_OK) {
    #else
    if (BAGetConfig(&config) != BA_OK) {
    #endif
        printf("Error: Failed to get config\n");
        #ifdef __amigaos4__
        cmd.IBonAmi->BACloseLibrary();
        #else
        BACloseLibrary();
        #endif
        return RETURN_ERROR;
    }
    
    /* Create TXT record if specified */
    if (numTxtArgs > 0) {
        #ifdef __amigaos4__
        txt = cmd.IBonAmi->BACreateTXTRecord();
        #else
        txt = BACreateTXTRecord();
        #endif
        if (!txt) {
            printf("Error: Failed to create TXT record\n");
            #ifdef __amigaos4__
            cmd.IBonAmi->BACloseLibrary();
            #else
            BACloseLibrary();
            #endif
            return RETURN_ERROR;
        }
        
        /* Add TXT record */
        for (LONG i = 0; i < numTxtArgs; i++) {
            char *key = txtArgs[i];
            char *value = strchr(key, '=');
            if (value) {
                *value++ = '\0';
                #ifdef __amigaos4__
                if (cmd.IBonAmi->BAAddTXTRecord(txt, key, value) != BA_OK) {
                #else
                if (BAAddTXTRecord(txt, key, value) != BA_OK) {
                #endif
                    printf("Error: Failed to add TXT record\n");
                    #ifdef __amigaos4__
                    cmd.IBonAmi->BAFreeTXTRecord(txt);
                    cmd.IBonAmi->BACloseLibrary();
                    #else
                    BAFreeTXTRecord(txt);
                    BACloseLibrary();
                    #endif
                    return RETURN_ERROR;
                }
            }
        }
    }
    
    /* Register service */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BARegisterService(name, type, port, txt) != BA_OK) {
    #else
    if (BARegisterService(name, type, port, txt) != BA_OK) {
    #endif
        printf("Error: Failed to register service\n");
        if (txt) {
            #ifdef __amigaos4__
            cmd.IBonAmi->BAFreeTXTRecord(txt);
            #else
            BAFreeTXTRecord(txt);
            #endif
        }
        #ifdef __amigaos4__
        cmd.IBonAmi->BACloseLibrary();
        #else
        BACloseLibrary();
        #endif
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    if (txt) {
        #ifdef __amigaos4__
        cmd.IBonAmi->BAFreeTXTRecord(txt);
        #else
        BAFreeTXTRecord(txt);
        #endif
    }
    #ifdef __amigaos4__
    cmd.IBonAmi->BACloseLibrary();
    #else
    BACloseLibrary();
    #endif
    
    printf("Service registered successfully\n");
    return RETURN_OK;
}

/* Handle unregister command */
static LONG handleUnregister(struct RDArgs *args) {
    char *name = NULL;
    char *type = NULL;

    /* Get arguments */
    if (args->RDA_Flags & RDA_NAME) {
        name = (char *)args->RDA_NAME;
    }
    if (args->RDA_Flags & RDA_TYPE) {
        type = (char *)args->RDA_TYPE;
    }

    /* Check required arguments */
    if (!name || !type) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[2]);
        return RETURN_ERROR;
    }

    /* Unregister service */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAUnregisterService(name, type) != BA_OK) {
    #else
    if (BAUnregisterService(name, type) != BA_OK) {
    #endif
        printf("Error: Failed to unregister service\n");
        return RETURN_ERROR;
    }

    printf("Service unregistered successfully\n");
    return RETURN_OK;
}

/* Handle list command */
static LONG handleList(struct RDArgs *args) {
    struct List services;
    struct BAServiceInfo *info;
    char *type = NULL;

    /* Get arguments */
    if (args->RDA_Flags & RDA_TYPE) {
        type = (char *)args->RDA_TYPE;
    }

    /* Check required arguments */
    if (!type) {
        printf("Error: TYPE argument is required\n");
        printUsage(&commands[3]);
        return RETURN_ERROR;
    }

    /* Initialize list */
    NewList(&services);

    /* Enumerate services */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAEnumerateServices(&services, type) != BA_OK) {
    #else
    if (BAEnumerateServices(&services, type) != BA_OK) {
    #endif
        printf("Error: Failed to enumerate services\n");
        return RETURN_ERROR;
    }

    /* Print results */
    printf("Services of type %s:\n", type);
    for (info = (struct BAServiceInfo *)services.lh_Head; info->node.ln_Succ; info = (struct BAServiceInfo *)info->node.ln_Succ) {
        printf("  %s - %s:%d\n", info->name, inet_ntoa(*(struct in_addr *)&info->ip), info->port);
    }

    return RETURN_OK;
}

/* Handle resolve command */
static LONG handleResolve(struct RDArgs *args) {
    struct BAServiceInfo info;
    char *name = NULL;
    char *type = NULL;

    /* Get arguments */
    if (args->RDA_Flags & RDA_NAME) {
        name = (char *)args->RDA_NAME;
    }
    if (args->RDA_Flags & RDA_TYPE) {
        type = (char *)args->RDA_TYPE;
    }

    /* Check required arguments */
    if (!name || !type) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[4]);
        return RETURN_ERROR;
    }

    /* Resolve service */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAGetServiceInfo(&info, name, type) != BA_OK) {
    #else
    if (BAGetServiceInfo(&info, name, type) != BA_OK) {
    #endif
        printf("Error: Failed to resolve service\n");
        return RETURN_ERROR;
    }

    printf("Service resolved:\n");
    printf("  Name: %s\n", info.name);
    printf("  Type: %s\n", info.type);
    printf("  Address: %s\n", inet_ntoa(*(struct in_addr *)&info.ip));
    printf("  Port: %d\n", info.port);
    printf("  TTL: %d\n", info.ttl);

    return RETURN_OK;
}

/* Handle monitor command */
static LONG handleMonitor(struct RDArgs *args) {
    char *name = NULL;
    char *type = NULL;
    LONG interval = 30;
    BOOL notify = FALSE;

    /* Get arguments */
    if (args->RDA_Flags & RDA_NAME) {
        name = (char *)args->RDA_NAME;
    }
    if (args->RDA_Flags & RDA_TYPE) {
        type = (char *)args->RDA_TYPE;
    }
    if (args->RDA_Flags & RDA_INTERVAL) {
        interval = *(LONG *)args->RDA_INTERVAL;
    }
    if (args->RDA_Flags & RDA_NOTIFY) {
        notify = TRUE;
    }

    /* Check required arguments */
    if (!name || !type) {
        printf("Error: NAME and TYPE arguments are required\n");
        printUsage(&commands[5]);
        return RETURN_ERROR;
    }

    /* Monitor service */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAMonitorService(name, type, interval, notify) != BA_OK) {
    #else
    if (BAMonitorService(name, type, interval, notify) != BA_OK) {
    #endif
        printf("Error: Failed to monitor service\n");
        return RETURN_ERROR;
    }

    printf("Monitoring service %s of type %s\n", name, type);
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

/* Handle config command */
static LONG handleConfig(struct RDArgs *args) {
    struct BAConfig config;
    char **setArgs = NULL;
    LONG numSetArgs = 0;

    /* Get arguments */
    if (args->RDA_Flags & RDA_SET) {
        setArgs = (char **)args->RDA_SET;
        numSetArgs = args->RDA_SET_Count;
    }

    /* Get current config */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAGetConfig(&config) != BA_OK) {
    #else
    if (BAGetConfig(&config) != BA_OK) {
    #endif
        printf("Error: Failed to get current configuration\n");
        return RETURN_ERROR;
    }

    /* Update config */
    for (LONG i = 0; i < numSetArgs; i++) {
        char *key = setArgs[i];
        char *value = strchr(key, '=');
        if (value) {
            *value++ = '\0';
            if (strcmp(key, "discovery-timeout") == 0) {
                config.discoveryTimeout = atoi(value);
            } else if (strcmp(key, "resolve-timeout") == 0) {
                config.resolveTimeout = atoi(value);
            } else if (strcmp(key, "ttl") == 0) {
                config.ttl = atoi(value);
            } else if (strcmp(key, "auto-reconnect") == 0) {
                config.autoReconnect = (strcmp(value, "true") == 0);
            }
        }
    }

    /* Set new config */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BASetConfig(&config) != BA_OK) {
    #else
    if (BASetConfig(&config) != BA_OK) {
    #endif
        printf("Error: Failed to set configuration\n");
        return RETURN_ERROR;
    }

    printf("Configuration updated successfully\n");
    return RETURN_OK;
}

/* Handle status command */
static LONG handleStatus(struct RDArgs *args) {
    struct BAConfig config;
    struct BAInterface interfaces[MAX_INTERFACES];
    ULONG numInterfaces = MAX_INTERFACES;

    /* Get configuration */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAGetConfig(&config) != BA_OK) {
    #else
    if (BAGetConfig(&config) != BA_OK) {
    #endif
        printf("Error: Failed to get configuration\n");
        return RETURN_ERROR;
    }

    /* Get interfaces */
    #ifdef __amigaos4__
    if (cmd.IBonAmi->BAGetInterfaces(interfaces, &numInterfaces) != BA_OK) {
    #else
    if (BAGetInterfaces(interfaces, &numInterfaces) != BA_OK) {
    #endif
        printf("Error: Failed to get interfaces\n");
        return RETURN_ERROR;
    }

    /* Print status */
    printf("BonAmi mDNS Daemon Status\n\n");
    printf("Configuration:\n");
    printf("  Discovery Timeout: %d seconds\n", config.discoveryTimeout);
    printf("  Resolve Timeout: %d seconds\n", config.resolveTimeout);
    printf("  TTL: %d seconds\n", config.ttl);
    printf("  Auto Reconnect: %s\n", config.autoReconnect ? "enabled" : "disabled");
    printf("\nInterfaces:\n");
    for (ULONG i = 0; i < numInterfaces; i++) {
        printf("  %s: %s (%s)\n", interfaces[i].name,
               inet_ntoa(interfaces[i].addr),
               interfaces[i].up ? "up" : "down");
    }

    return RETURN_OK;
}

/* Handle signals */
static void handleSignals(void) {
    ULONG signals = SetSignal(0, 0);
    if (signals & SIGBREAKF_CTRL_C) {
        /* Graceful exit */
        cleanupCommand();
        exit(RETURN_OK);
    } else if (signals & SIGBREAKF_CTRL_D) {
        /* Toggle debug output */
        printf("Debug output toggled\n");
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