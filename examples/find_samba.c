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

/* Service type for Samba */
#define SAMBA_SERVICE_TYPE "_smb._tcp"

/* Timeout in seconds */
#define DISCOVERY_TIMEOUT 5

/* Main function */
int main(int argc, char **argv)
{
    struct Library *bonamiBase;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
    struct BAConfig config;
    struct BATXTRecord *txt = NULL;
    struct BAServiceList *services = NULL;
    LONG result;
    
    /* Open library */
    #ifdef __amigaos4__
    bonamiBase = IExec->OpenLibrary("bonami.library", 40);
    if (!bonamiBase) {
        printf("Failed to open bonami.library\n");
        return RETURN_ERROR;
    }
    
    IBonAmi = (struct BonAmiIFace *)IExec->GetInterface(bonamiBase, "main", 1, NULL);
    if (!IBonAmi) {
        printf("Failed to get BonAmi interface\n");
        IExec->CloseLibrary(bonamiBase);
        return RETURN_ERROR;
    }
    #else
    bonamiBase = OpenLibrary("bonami.library", 40);
    if (!bonamiBase) {
        printf("Failed to open bonami.library\n");
        return RETURN_ERROR;
    }
    #endif
    
    /* Get current configuration */
    #ifdef __amigaos4__
    if (IBonAmi->BAGetConfig(&config) != BA_OK) {
    #else
    if (BAGetConfig(&config) != BA_OK) {
    #endif
        printf("Failed to get configuration\n");
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)IBonAmi);
        IExec->CloseLibrary(bonamiBase);
        #else
        CloseLibrary(bonamiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Create TXT record for discovery */
    #ifdef __amigaos4__
    txt = IBonAmi->BACreateTXTRecord();
    #else
    txt = BACreateTXTRecord();
    #endif
    if (!txt) {
        printf("Failed to create TXT record\n");
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)IBonAmi);
        IExec->CloseLibrary(bonamiBase);
        #else
        CloseLibrary(bonamiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Start discovery */
    printf("Searching for Samba servers...\n");
    #ifdef __amigaos4__
    result = IBonAmi->BAStartDiscovery(SAMBA_SERVICE_TYPE, txt);
    #else
    result = BAStartDiscovery(SAMBA_SERVICE_TYPE, txt);
    #endif
    if (result != BA_OK) {
        printf("Failed to start discovery\n");
        #ifdef __amigaos4__
        IBonAmi->BAFreeTXTRecord(txt);
        IExec->DropInterface((struct Interface *)IBonAmi);
        IExec->CloseLibrary(bonamiBase);
        #else
        BAFreeTXTRecord(txt);
        CloseLibrary(bonamiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Wait for discovery */
    Delay(DISCOVERY_TIMEOUT * 50);  /* 50 ticks per second */
    
    /* Get discovered services */
    #ifdef __amigaos4__
    services = IBonAmi->BAGetDiscoveredServices(SAMBA_SERVICE_TYPE);
    #else
    services = BAGetDiscoveredServices(SAMBA_SERVICE_TYPE);
    #endif
    if (!services) {
        printf("No Samba servers found\n");
        #ifdef __amigaos4__
        IBonAmi->BAStopDiscovery(SAMBA_SERVICE_TYPE);
        IBonAmi->BAFreeTXTRecord(txt);
        IExec->DropInterface((struct Interface *)IBonAmi);
        IExec->CloseLibrary(bonamiBase);
        #else
        BAStopDiscovery(SAMBA_SERVICE_TYPE);
        BAFreeTXTRecord(txt);
        CloseLibrary(bonamiBase);
        #endif
        return RETURN_OK;
    }
    
    /* Print discovered services */
    printf("\nFound Samba servers:\n");
    printf("-------------------\n");
    
    struct BAService *service;
    for (service = services->services; service; service = service->next) {
        printf("Server: %s\n", service->name);
        printf("  Host: %s\n", service->host);
        printf("  Port: %ld\n", service->port);
        
        if (service->txt) {
            struct BATXTRecord *record;
            for (record = service->txt; record; record = record->next) {
                printf("  %s=%s\n", record->key, record->value);
            }
        }
        printf("\n");
    }
    
    /* Cleanup */
    #ifdef __amigaos4__
    IBonAmi->BAFreeServiceList(services);
    IBonAmi->BAStopDiscovery(SAMBA_SERVICE_TYPE);
    IBonAmi->BAFreeTXTRecord(txt);
    IExec->DropInterface((struct Interface *)IBonAmi);
    IExec->CloseLibrary(bonamiBase);
    #else
    BAFreeServiceList(services);
    BAStopDiscovery(SAMBA_SERVICE_TYPE);
    BAFreeTXTRecord(txt);
    CloseLibrary(bonamiBase);
    #endif
    
    return RETURN_OK;
} 