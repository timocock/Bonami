#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bonami.h>
#include <exec/types.h>
#include <exec/lists.h>
#include <dos/dos.h>
#include <dos/rdargs.h>
#include <stdio.h>
#include <string.h>

/* Version string */
static const char *version = "$VER: find_samba 40.0 (01.01.2024)";

/* Command line template */
static const char *template = "TIMEOUT/N";

/* Main function */
int main(int argc, char *argv[])
{
    struct RDArgs *args;
    struct List services;
    struct BAServiceInfo *info;
    LONG timeout = 5;  /* Default timeout in seconds */
    LONG result;
    
    /* Parse command line */
    args = ReadArgs(template, NULL, NULL);
    if (args) {
        if (args->RDA_Flags & RDAF_TIMEOUT) {
            timeout = *(LONG *)args->RDA_TIMEOUT;
        }
        FreeArgs(args);
    }
    
    /* Initialize service list */
    NewList(&services);
    
    /* Open bonami.library */
    struct Library *bonamiBase = OpenLibrary("bonami.library", 40);
    if (!bonamiBase) {
        printf("Error: Failed to open bonami.library\n");
        return 1;
    }
    
    /* Initialize library */
    struct BABase *base = BAOpen();
    if (!base) {
        printf("Error: Failed to initialize bonami.library\n");
        CloseLibrary(bonamiBase);
        return 1;
    }
    
    printf("Searching for Samba shares...\n");
    
    /* Start discovery */
    result = BAStartDiscovery(base, "_smb._tcp.local", NULL);
    if (result != BA_OK) {
        printf("Error: Failed to start discovery: %ld\n", result);
        BAClose(base);
        CloseLibrary(bonamiBase);
        return 1;
    }
    
    /* Wait for timeout */
    Delay(timeout * 50);  /* Convert seconds to ticks */
    
    /* Enumerate services */
    result = BAEnumerateServices(&services, "_smb._tcp.local");
    if (result != BA_OK) {
        printf("Error: Failed to enumerate services: %ld\n", result);
        BAStopDiscovery(base, "_smb._tcp.local");
        BAClose(base);
        CloseLibrary(bonamiBase);
        return 1;
    }
    
    /* Print results */
    if (IsListEmpty(&services)) {
        printf("No Samba shares found\n");
    } else {
        printf("\nFound Samba shares:\n");
        printf("-------------------\n");
        
        for (info = (struct BAServiceInfo *)services.lh_Head;
             info->node.ln_Succ;
             info = (struct BAServiceInfo *)info->node.ln_Succ) {
            
            printf("Name: %s\n", info->name);
            printf("Host: %s\n", info->host);
            printf("Port: %ld\n", info->port);
            
            /* Print TXT records */
            if (info->txt) {
                struct BATXTRecord *txt;
                printf("Properties:\n");
                for (txt = info->txt; txt; txt = txt->next) {
                    printf("  %s = %s\n", txt->key, txt->value);
                }
            }
            
            printf("-------------------\n");
        }
    }
    
    /* Stop discovery */
    BAStopDiscovery(base, "_smb._tcp.local");
    
    /* Cleanup */
    BAClose(base);
    CloseLibrary(bonamiBase);
    
    return 0;
} 