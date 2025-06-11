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

/* Discovery callback */
static void discoveryCallback(struct BAService *service, APTR userData)
{
    printf("Found Samba server: %s\n", service->name);
    printf("  Host: %s\n", service->host);
    printf("  Port: %ld\n", service->port);
    
    if (service->txt) {
        printf("  TXT: %s\n", service->txt);
    }
    printf("\n");
}

/* Main function */
int main(int argc, char **argv)
{
    struct Library *bonamiBase;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
    struct BADiscovery discovery;
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
    
    /* Start discovery */
    printf("Searching for Samba servers...\n");
    
    discovery.type = SAMBA_SERVICE_TYPE;
    discovery.callback = discoveryCallback;
    discovery.userData = NULL;
    
    #ifdef __amigaos4__
    result = IBonAmi->BAStartDiscovery(&discovery);
    #else
    result = BAStartDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Failed to start discovery\n");
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)IBonAmi);
        IExec->CloseLibrary(bonamiBase);
        #else
        CloseLibrary(bonamiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Wait for discovery */
    Delay(DISCOVERY_TIMEOUT * 50);  /* 50 ticks per second */
    
    /* Stop discovery */
    #ifdef __amigaos4__
    result = IBonAmi->BAStopDiscovery(&discovery);
    #else
    result = BAStopDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        printf("Failed to stop discovery\n");
    }
    
    /* Cleanup */
    #ifdef __amigaos4__
    IExec->DropInterface((struct Interface *)IBonAmi);
    IExec->CloseLibrary(bonamiBase);
    #else
    CloseLibrary(bonamiBase);
    #endif
    
    return RETURN_OK;
} 