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
    const char *template;
    const char *description;
    LONG (*handler)(struct RDArgs *args);
};

/* Forward declarations */
static LONG cmd_discover(struct RDArgs *args);
static LONG cmd_register(struct RDArgs *args);
static LONG cmd_unregister(struct RDArgs *args);
static LONG cmd_list(struct RDArgs *args);
static LONG cmd_resolve(struct RDArgs *args);
static LONG cmd_monitor(struct RDArgs *args);
static LONG cmd_config(struct RDArgs *args);
static LONG cmd_status(struct RDArgs *args);
static void print_usage(const char *cmd);
static void print_help(void);

/* Command table */
static struct Command commands[] = {
    {
        "discover",
        "TYPE/K, FILTER/K, TIMEOUT/N",
        "Discover services of specified type",
        cmd_discover
    },
    {
        "register",
        "NAME/K, TYPE/K, PORT/N, TXT/M",
        "Register a new service",
        cmd_register
    },
    {
        "unregister",
        "NAME/K, TYPE/K",
        "Unregister a service",
        cmd_unregister
    },
    {
        "list",
        "TYPE/K",
        "List discovered services",
        cmd_list
    },
    {
        "resolve",
        "NAME/K, TYPE/K",
        "Resolve service details",
        cmd_resolve
    },
    {
        "monitor",
        "NAME/K, TYPE/K, INTERVAL/N, NOTIFY/S",
        "Monitor service availability",
        cmd_monitor
    },
    {
        "config",
        "SET/M",
        "Get or set configuration",
        cmd_config
    },
    {
        "status",
        "",
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
    struct RDArgs *args;
    
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
            /* Parse arguments */
            args = ReadArgs(cmd->template, argv + 2, NULL);
            if (!args) {
                if (IoErr() == ERROR_REQUIRED_ARG_MISSING) {
                    print_usage(cmd->name);
                } else {
                    printf("Error: Invalid arguments\n");
                }
                CloseLibrary(bonami);
                return RETURN_ERROR;
            }
            
            /* Execute command */
            LONG result = cmd->handler(args);
            FreeArgs(args);
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
static LONG cmd_discover(struct RDArgs *args)
{
    struct BonamiDiscovery discovery;
    struct BonamiFilter filter;
    LONG timeout = 5;
    
    /* Get arguments */
    strncpy(discovery.type, (char *)args->RDA_Args[0], sizeof(discovery.type) - 1);
    discovery.callback = NULL;
    discovery.userData = NULL;
    
    if (args->RDA_Args[1]) {  /* FILTER */
        char *key = (char *)args->RDA_Args[1];
        char *value = strchr(key, '=');
        if (value) {
            *value++ = '\0';
            strncpy(filter.txtKey, key, sizeof(filter.txtKey) - 1);
            strncpy(filter.txtValue, value, sizeof(filter.txtValue) - 1);
            filter.wildcard = FALSE;
        }
    }
    
    if (args->RDA_Args[2]) {  /* TIMEOUT */
        timeout = *(LONG *)args->RDA_Args[2];
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
static LONG cmd_register(struct RDArgs *args)
{
    struct BonamiService service;
    struct BonamiTXTRecord *txt = NULL;
    struct BonamiTXTRecord **txt_ptr = &txt;
    char **txt_args;
    
    /* Get arguments */
    strncpy(service.name, (char *)args->RDA_Args[0], sizeof(service.name) - 1);
    strncpy(service.type, (char *)args->RDA_Args[1], sizeof(service.type) - 1);
    service.port = *(LONG *)args->RDA_Args[2];
    service.txt = NULL;
    
    /* Parse TXT records */
    txt_args = (char **)args->RDA_Args[3];
    while (*txt_args) {
        char *key = *txt_args;
        char *value = strchr(key, '=');
        if (value) {
            *value++ = '\0';
            struct BonamiTXTRecord *new_txt = BonamiCreateTXTRecord(key, value);
            if (new_txt) {
                *txt_ptr = new_txt;
                txt_ptr = &new_txt->next;
            }
        }
        txt_args++;
    }
    
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
static LONG cmd_unregister(struct RDArgs *args)
{
    LONG result = BonamiUnregisterService(
        (char *)args->RDA_Args[0],  /* NAME */
        (char *)args->RDA_Args[1]   /* TYPE */
    );
    
    if (result != BONAMI_OK) {
        printf("Error: Failed to unregister service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* List command */
static LONG cmd_list(struct RDArgs *args)
{
    struct BonamiService services[256];
    ULONG numServices = 256;
    const char *type = (char *)args->RDA_Args[0];
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
static LONG cmd_resolve(struct RDArgs *args)
{
    struct BonamiService service;
    
    LONG result = BonamiResolveService(
        (char *)args->RDA_Args[0],  /* NAME */
        (char *)args->RDA_Args[1],  /* TYPE */
        &service
    );
    
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
static LONG cmd_monitor(struct RDArgs *args)
{
    LONG interval = 5;
    BOOL notifyOffline = FALSE;
    
    if (args->RDA_Args[2]) {  /* INTERVAL */
        interval = *(LONG *)args->RDA_Args[2];
    }
    
    if (args->RDA_Args[3]) {  /* NOTIFY */
        notifyOffline = TRUE;
    }
    
    LONG result = BonamiMonitorService(
        (char *)args->RDA_Args[0],  /* NAME */
        (char *)args->RDA_Args[1],  /* TYPE */
        interval,
        notifyOffline
    );
    
    if (result != BONAMI_OK) {
        printf("Error: Failed to monitor service (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    return RETURN_OK;
}

/* Config command */
static LONG cmd_config(struct RDArgs *args)
{
    struct BonamiConfig config;
    char **set_args;
    
    /* Get current config */
    LONG result = BonamiGetConfig(&config);
    if (result != BONAMI_OK) {
        printf("Error: Failed to get configuration (%ld)\n", result);
        return RETURN_ERROR;
    }
    
    if (!args->RDA_Args[0]) {  /* No SET arguments */
        printf("Discovery Timeout: %ld seconds\n", config.discoveryTimeout);
        printf("Resolve Timeout: %ld seconds\n", config.resolveTimeout);
        printf("TTL: %ld seconds\n", config.ttl);
        printf("Auto Reconnect: %s\n", config.autoReconnect ? "Yes" : "No");
        return RETURN_OK;
    }
    
    /* Parse SET arguments */
    set_args = (char **)args->RDA_Args[0];
    while (*set_args) {
        char *key = *set_args;
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
        set_args++;
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
static LONG cmd_status(struct RDArgs *args)
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
            printf("Usage: bactl %s %s\n", c->name, c->template);
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