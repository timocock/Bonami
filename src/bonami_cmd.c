#include <exec/types.h>
#include <exec/memory.h>
#include <exec/libraries.h>
#include <exec/ports.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <string.h>
#include <stdio.h>

#include "../include/bonami.h"

/* Command structure */
struct Command {
    const char *name;
    const char *usage;
    const char *description;
    LONG (*handler)(int argc, char **argv);
};

/* Forward declarations */
static LONG cmd_discover(int argc, char **argv);
static LONG cmd_register(int argc, char **argv);
static LONG cmd_unregister(int argc, char **argv);
static LONG cmd_list(int argc, char **argv);
static LONG cmd_resolve(int argc, char **argv);
static LONG cmd_monitor(int argc, char **argv);
static LONG cmd_config(int argc, char **argv);
static LONG cmd_status(int argc, char **argv);
static void print_usage(const char *cmd);
static void print_help(void);

/* Command table */
static struct Command commands[] = {
    {
        "discover",
        "discover <type> [--filter key=value] [--timeout seconds]",
        "Discover services of specified type",
        cmd_discover
    },
    {
        "register",
        "register <name> <type> <port> [--txt key=value]...",
        "Register a new service",
        cmd_register
    },
    {
        "unregister",
        "unregister <name> <type>",
        "Unregister a service",
        cmd_unregister
    },
    {
        "list",
        "list [type]",
        "List discovered services",
        cmd_list
    },
    {
        "resolve",
        "resolve <name> <type>",
        "Resolve service details",
        cmd_resolve
    },
    {
        "monitor",
        "monitor <name> <type> [--interval seconds] [--notify-offline]",
        "Monitor service availability",
        cmd_monitor
    },
    {
        "config",
        "config [--set key=value]...",
        "Get or set configuration",
        cmd_config
    },
    {
        "status",
        "status",
        "Show daemon status",
        cmd_status
    },
    { NULL, NULL, NULL, NULL }
};

/* Main function */
int main(int argc, char **argv)
{
    struct Library *bonami;
    struct Command *cmd;
    
    /* Check arguments */
    if (argc < 2) {
        print_help();
        return RETURN_ERROR;
    }
    
    /* Open library */
    bonami = OpenLibrary("bonami.library", 0);
    if (!bonami) {
        printf("Error: Could not open bonami.library\n");
        return RETURN_ERROR;
    }
    
    /* Find command */
    for (cmd = commands; cmd->name; cmd++) {
        if (strcmp(argv[1], cmd->name) == 0) {
            /* Execute command */
            LONG result = cmd->handler(argc - 2, argv + 2);
            CloseLibrary(bonami);
            return result;
        }
    }
    
    /* Unknown command */
    printf("Error: Unknown command '%s'\n", argv[1]);
    print_help();
    CloseLibrary(bonami);
    return RETURN_ERROR;
}

/* Discover command */
static LONG cmd_discover(int argc, char **argv)
{
    struct BonamiDiscovery discovery;
    struct BonamiFilter filter;
    LONG timeout = 5;
    int i;
    
    if (argc < 1) {
        print_usage("discover");
        return RETURN_ERROR;
    }
    
    /* Parse arguments */
    strncpy(discovery.type, argv[0], sizeof(discovery.type) - 1);
    discovery.callback = NULL;
    discovery.userData = NULL;
    
    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--filter=", 9) == 0) {
            char *key = argv[i] + 9;
            char *value = strchr(key, '=');
            if (value) {
                *value++ = '\0';
                strncpy(filter.txtKey, key, sizeof(filter.txtKey) - 1);
                strncpy(filter.txtValue, value, sizeof(filter.txtValue) - 1);
                filter.wildcard = FALSE;
            }
        } else if (strncmp(argv[i], "--timeout=", 10) == 0) {
            timeout = atoi(argv[i] + 10);
        }
    }
    
    /* Start discovery */
    LONG result = BonamiStartDiscovery(&discovery);
    if (result != BONAMI_OK) {
        printf("Error: Failed to start discovery (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    /* Wait for timeout */
    Delay(timeout * 50);
    
    /* Stop discovery */
    BonamiStopDiscovery(&discovery);
    return RETURN_OK;
}

/* Register command */
static LONG cmd_register(int argc, char **argv)
{
    struct BonamiService service;
    struct BonamiTXTRecord *txt = NULL;
    int i;
    
    if (argc < 3) {
        print_usage("register");
        return RETURN_ERROR;
    }
    
    /* Parse arguments */
    strncpy(service.name, argv[0], sizeof(service.name) - 1);
    strncpy(service.type, argv[1], sizeof(service.type) - 1);
    service.port = atoi(argv[2]);
    service.txt = NULL;
    
    /* Parse TXT records */
    for (i = 3; i < argc; i++) {
        if (strncmp(argv[i], "--txt=", 6) == 0) {
            char *key = argv[i] + 6;
            char *value = strchr(key, '=');
            if (value) {
                *value++ = '\0';
                struct BonamiTXTRecord *new_txt = BonamiCreateTXTRecord(key, value);
                if (new_txt) {
                    new_txt->next = txt;
                    txt = new_txt;
                }
            }
        }
    }
    service.txt = txt;
    
    /* Register service */
    LONG result = BonamiRegisterService(&service);
    
    /* Clean up */
    while (txt) {
        struct BonamiTXTRecord *next = txt->next;
        BonamiFreeTXTRecord(txt);
        txt = next;
    }
    
    if (result != BONAMI_OK) {
        printf("Error: Failed to register service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Unregister command */
static LONG cmd_unregister(int argc, char **argv)
{
    if (argc < 2) {
        print_usage("unregister");
        return RETURN_ERROR;
    }
    
    LONG result = BonamiUnregisterService(argv[0], argv[1]);
    if (result != BONAMI_OK) {
        printf("Error: Failed to unregister service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* List command */
static LONG cmd_list(int argc, char **argv)
{
    struct BonamiService services[256];
    ULONG numServices = 256;
    const char *type = argc > 0 ? argv[0] : NULL;
    int i;
    
    LONG result = BonamiGetServices(type, services, &numServices);
    if (result != BONAMI_OK) {
        printf("Error: Failed to get services (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    /* Print services */
    for (i = 0; i < numServices; i++) {
        printf("%s (%s) on %s:%d\n",
               services[i].name,
               services[i].type,
               services[i].hostname,
               services[i].port);
        
        /* Print TXT records */
        struct BonamiTXTRecord *txt = services[i].txt;
        while (txt) {
            printf("  %s=%s\n", txt->key, txt->value);
            txt = txt->next;
        }
    }
    
    return RETURN_OK;
}

/* Resolve command */
static LONG cmd_resolve(int argc, char **argv)
{
    struct BonamiService service;
    
    if (argc < 2) {
        print_usage("resolve");
        return RETURN_ERROR;
    }
    
    LONG result = BonamiResolveService(argv[0], argv[1], &service);
    if (result != BONAMI_OK) {
        printf("Error: Failed to resolve service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    /* Print service details */
    printf("Name: %s\n", service.name);
    printf("Type: %s\n", service.type);
    printf("Host: %s\n", service.hostname);
    printf("Port: %d\n", service.port);
    
    /* Print TXT records */
    struct BonamiTXTRecord *txt = service.txt;
    while (txt) {
        printf("TXT: %s=%s\n", txt->key, txt->value);
        txt = txt->next;
    }
    
    return RETURN_OK;
}

/* Monitor command */
static LONG cmd_monitor(int argc, char **argv)
{
    LONG interval = 5;
    BOOL notifyOffline = FALSE;
    int i;
    
    if (argc < 2) {
        print_usage("monitor");
        return RETURN_ERROR;
    }
    
    /* Parse arguments */
    for (i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--interval=", 11) == 0) {
            interval = atoi(argv[i] + 11);
        } else if (strcmp(argv[i], "--notify-offline") == 0) {
            notifyOffline = TRUE;
        }
    }
    
    LONG result = BonamiMonitorService(argv[0], argv[1], interval, notifyOffline);
    if (result != BONAMI_OK) {
        printf("Error: Failed to monitor service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Config command */
static LONG cmd_config(int argc, char **argv)
{
    struct BonamiConfig config;
    int i;
    
    if (argc == 0) {
        /* Get current config */
        LONG result = BonamiGetConfig(&config);
        if (result != BONAMI_OK) {
            printf("Error: Failed to get configuration (%ld)\n", result);
            return RETURN_ERROR;
        }
        
        printf("Discovery Timeout: %ld seconds\n", config.discoveryTimeout);
        printf("Resolve Timeout: %ld seconds\n", config.resolveTimeout);
        printf("TTL: %ld seconds\n", config.ttl);
        printf("Auto Reconnect: %s\n", config.autoReconnect ? "Yes" : "No");
        
        return RETURN_OK;
    }
    
    /* Get current config */
    LONG result = BonamiGetConfig(&config);
    if (result != BONAMI_OK) {
        printf("Error: Failed to get configuration (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    /* Parse arguments */
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "--set=", 6) == 0) {
            char *key = argv[i] + 6;
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
                    config.autoReconnect = strcmp(value, "yes") == 0;
                }
            }
        }
    }
    
    /* Set new config */
    result = BonamiSetConfig(&config);
    if (result != BONAMI_OK) {
        printf("Error: Failed to set configuration (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Status command */
static LONG cmd_status(int argc, char **argv)
{
    struct BonamiInterface interfaces[256];
    ULONG numInterfaces = 256;
    int i;
    
    /* Get interfaces */
    LONG result = BonamiGetInterfaces(interfaces, &numInterfaces);
    if (result != BONAMI_OK) {
        printf("Error: Failed to get interfaces (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    /* Print interfaces */
    printf("Network Interfaces:\n");
    for (i = 0; i < numInterfaces; i++) {
        printf("%s: %s %s\n",
               interfaces[i].name,
               interfaces[i].up ? "UP" : "DOWN",
               interfaces[i].preferred ? "(Preferred)" : "");
    }
    
    return RETURN_OK;
}

/* Print command usage */
static void print_usage(const char *cmd)
{
    struct Command *c;
    
    for (c = commands; c->name; c++) {
        if (strcmp(c->name, cmd) == 0) {
            printf("Usage: bactl %s\n", c->usage);
            return;
        }
    }
}

/* Print help */
static void print_help(void)
{
    struct Command *c;
    
    printf("BonAmi mDNS Control Utility (bactl)\n\n");
    printf("Usage: bactl <command> [options]\n\n");
    printf("Commands:\n");
    
    for (c = commands; c->name; c++) {
        printf("  %-12s %s\n", c->name, c->description);
    }
    
    printf("\nUse 'bactl <command>' for more information about a command.\n");
} 