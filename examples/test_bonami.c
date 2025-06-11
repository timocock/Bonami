#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bonami.h>
#include <stdio.h>
#include <string.h>

/* Version string */
static const char *version = "$VER: test_bonami 40.0 (01.01.2024)";

/* Test configuration */
#define TEST_SERVICE_NAME "test-service"
#define TEST_SERVICE_TYPE "_test._tcp"
#define TEST_SERVICE_PORT 1234
#define TEST_HOSTNAME "test-host"
#define TEST_TIMEOUT 5

/* Test state */
struct TestState {
    struct Library *BonAmiBase;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
    struct BAConfig config;
    struct BATXTRecord *txt;
    BOOL success;
};

/* Forward declarations */
static LONG runTest(const char *name, LONG (*testFunc)(struct TestState *));
static LONG testLibraryOpen(struct TestState *state);
static LONG testServiceRegistration(struct TestState *state);
static LONG testServiceDiscovery(struct TestState *state);
static LONG testServiceMonitoring(struct TestState *state);
static LONG testTXTRecords(struct TestState *state);
static LONG testConfiguration(struct TestState *state);
static LONG testInterfaceManagement(struct TestState *state);
static LONG testServiceUpdates(struct TestState *state);
static LONG testServiceEnumeration(struct TestState *state);
static LONG testErrorHandling(struct TestState *state);

/* Main test function */
int main(int argc, char **argv)
{
    struct TestState state;
    LONG result = RETURN_OK;
    
    /* Initialize state */
    memset(&state, 0, sizeof(state));
    
    /* Run tests */
    printf("Running BonAmi library tests...\n\n");
    
    if (runTest("Library Open/Close", testLibraryOpen) != RETURN_OK) {
        printf("Failed to initialize library\n");
        return RETURN_ERROR;
    }
    
    if (runTest("Service Registration", testServiceRegistration) != RETURN_OK) {
        printf("Service registration tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Service Discovery", testServiceDiscovery) != RETURN_OK) {
        printf("Service discovery tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Service Monitoring", testServiceMonitoring) != RETURN_OK) {
        printf("Service monitoring tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("TXT Records", testTXTRecords) != RETURN_OK) {
        printf("TXT record tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Configuration", testConfiguration) != RETURN_OK) {
        printf("Configuration tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Interface Management", testInterfaceManagement) != RETURN_OK) {
        printf("Interface management tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Service Updates", testServiceUpdates) != RETURN_OK) {
        printf("Service update tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Service Enumeration", testServiceEnumeration) != RETURN_OK) {
        printf("Service enumeration tests failed\n");
        result = RETURN_ERROR;
    }
    
    if (runTest("Error Handling", testErrorHandling) != RETURN_ERROR) {
        printf("Error handling tests failed\n");
        result = RETURN_ERROR;
    }
    
    /* Print summary */
    printf("\nTest Summary:\n");
    printf("-------------\n");
    printf("All tests %s\n", result == RETURN_OK ? "PASSED" : "FAILED");
    
    return result;
}

/* Run a single test */
static LONG runTest(const char *name, LONG (*testFunc)(struct TestState *))
{
    printf("Running test: %s\n", name);
    printf("----------------------------------------\n");
    
    LONG result = testFunc(&state);
    
    printf("Test %s: %s\n\n", name, result == RETURN_OK ? "PASSED" : "FAILED");
    return result;
}

/* Test library open/close */
static LONG testLibraryOpen(struct TestState *state)
{
    /* Open library */
    #ifdef __amigaos4__
    state->BonAmiBase = IExec->OpenLibrary("bonami.library", 40);
    if (!state->BonAmiBase) {
        printf("Failed to open bonami.library\n");
        return RETURN_ERROR;
    }
    
    state->IBonAmi = (struct BonAmiIFace *)IExec->GetInterface(state->BonAmiBase, "main", 1, NULL);
    if (!state->IBonAmi) {
        printf("Failed to get BonAmi interface\n");
        IExec->CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    #else
    state->BonAmiBase = OpenLibrary("bonami.library", 40);
    if (!state->BonAmiBase) {
        printf("Failed to open bonami.library\n");
        return RETURN_ERROR;
    }
    #endif
    
    /* Get config */
    #ifdef __amigaos4__
    if (state->IBonAmi->BAGetConfig(&state->config) != BA_OK) {
    #else
    if (BAGetConfig(&state->config) != BA_OK) {
    #endif
        printf("Failed to get config\n");
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Close library */
    #ifdef __amigaos4__
    IExec->DropInterface((struct Interface *)state->IBonAmi);
    IExec->CloseLibrary(state->BonAmiBase);
    state->IBonAmi = NULL;
    #else
    CloseLibrary(state->BonAmiBase);
    #endif
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test service registration */
static LONG testServiceRegistration(struct TestState *state)
{
    LONG result;
    
    /* Open library */
    #ifdef __amigaos4__
    state->BonAmiBase = IExec->OpenLibrary("bonami.library", 40);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    state->IBonAmi = (struct BonAmiIFace *)IExec->GetInterface(state->BonAmiBase, "main", 1, NULL);
    if (!state->IBonAmi) {
        IExec->CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    #else
    state->BonAmiBase = OpenLibrary("bonami.library", 40);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    #endif
    
    /* Create TXT record */
    #ifdef __amigaos4__
    state->txt = state->IBonAmi->BACreateTXTRecord();
    #else
    state->txt = BACreateTXTRecord();
    #endif
    if (!state->txt) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Add TXT record */
    #ifdef __amigaos4__
    result = state->IBonAmi->BAAddTXTRecord(state->txt, "test-key", "test-value");
    #else
    result = BAAddTXTRecord(state->txt, "test-key", "test-value");
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        state->IBonAmi->BAFreeTXTRecord(state->txt);
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        BAFreeTXTRecord(state->txt);
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Register service */
    #ifdef __amigaos4__
    result = state->IBonAmi->BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 
                                             TEST_SERVICE_PORT, state->txt);
    #else
    result = BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 
                             TEST_SERVICE_PORT, state->txt);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        state->IBonAmi->BAFreeTXTRecord(state->txt);
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        BAFreeTXTRecord(state->txt);
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Wait for registration */
    Delay(50);
    
    /* Unregister service */
    #ifdef __amigaos4__
    result = state->IBonAmi->BAUnregisterService(TEST_SERVICE_NAME);
    #else
    result = BAUnregisterService(TEST_SERVICE_NAME);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        state->IBonAmi->BAFreeTXTRecord(state->txt);
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        BAFreeTXTRecord(state->txt);
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    #ifdef __amigaos4__
    state->IBonAmi->BAFreeTXTRecord(state->txt);
    IExec->DropInterface((struct Interface *)state->IBonAmi);
    IExec->CloseLibrary(state->BonAmiBase);
    state->IBonAmi = NULL;
    #else
    BAFreeTXTRecord(state->txt);
    CloseLibrary(state->BonAmiBase);
    #endif
    state->BonAmiBase = NULL;
    state->txt = NULL;
    
    return RETURN_OK;
}

/* Test service discovery */
static LONG testServiceDiscovery(struct TestState *state)
{
    LONG result;
    struct BAServiceList *services;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Start discovery */
    result = BAStartDiscovery(TEST_SERVICE_TYPE, NULL);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for discovery */
    Delay(50);
    
    /* Get services */
    services = BAGetServices(TEST_SERVICE_TYPE);
    if (!services) {
        BAStopDiscovery(TEST_SERVICE_TYPE);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Print services */
    struct BAServiceList *current;
    for (current = services; current; current = current->next) {
        printf("Found service: %s\n", current->name);
    }
    
    /* Cleanup */
    BAFreeServiceList(services);
    BAStopDiscovery(TEST_SERVICE_TYPE);
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test service monitoring */
static LONG testServiceMonitoring(struct TestState *state)
{
    LONG result;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Start monitoring */
    result = BAMonitorService(TEST_SERVICE_NAME);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for monitoring */
    Delay(50);
    
    /* Stop monitoring */
    result = BAStopMonitoring(TEST_SERVICE_NAME);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test TXT records */
static LONG testTXTRecords(struct TestState *state)
{
    LONG result;
    struct BATXTRecord *txt;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Create TXT record */
    txt = BACreateTXTRecord();
    if (!txt) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Add multiple TXT records */
    result = BAAddTXTRecord(txt, "key1", "value1");
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    result = BAAddTXTRecord(txt, "key2", "value2");
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Register service with TXT records */
    result = BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 
                             TEST_SERVICE_PORT, txt);
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for registration */
    Delay(50);
    
    /* Unregister service */
    result = BAUnregisterService(TEST_SERVICE_NAME);
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    BAFreeTXTRecord(txt);
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test configuration */
static LONG testConfiguration(struct TestState *state)
{
    LONG result;
    struct BAConfig config;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Get current config */
    result = BAGetConfig(&config);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Modify config */
    config.debug = TRUE;
    config.log_level = LOG_DEBUG;
    
    /* Set new config */
    result = BASetConfig(&config);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Get config again to verify */
    result = BAGetConfig(&config);
    if (result != BA_OK || !config.debug || config.log_level != LOG_DEBUG) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test interface management */
static LONG testInterfaceManagement(struct TestState *state)
{
    LONG result;
    struct BAInterface *interfaces;
    struct BAInterface *preferred;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Get interfaces */
    interfaces = BAGetInterfaces();
    if (!interfaces) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Print interfaces */
    struct BAInterface *current;
    for (current = interfaces; current; current = current->next) {
        printf("Interface: %s\n", current->name);
    }
    
    /* Set preferred interface */
    if (interfaces) {
        result = BASetPreferredInterface(interfaces->name);
        if (result != BA_OK) {
            BAFreeInterfaceList(interfaces);
            CloseLibrary(state->BonAmiBase);
            return RETURN_ERROR;
        }
    }
    
    /* Get preferred interface */
    preferred = BAGetPreferredInterface();
    if (!preferred) {
        BAFreeInterfaceList(interfaces);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    BAFreeInterfaceList(preferred);
    BAFreeInterfaceList(interfaces);
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test service updates */
static LONG testServiceUpdates(struct TestState *state)
{
    LONG result;
    struct BATXTRecord *txt;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Create TXT record */
    txt = BACreateTXTRecord();
    if (!txt) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Add TXT record */
    result = BAAddTXTRecord(txt, "key1", "value1");
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Register service */
    result = BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 
                             TEST_SERVICE_PORT, txt);
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for registration */
    Delay(50);
    
    /* Update TXT record */
    result = BAAddTXTRecord(txt, "key2", "value2");
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        BAUnregisterService(TEST_SERVICE_NAME);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Update service */
    result = BAUpdateService(TEST_SERVICE_NAME, txt);
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        BAUnregisterService(TEST_SERVICE_NAME);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for update */
    Delay(50);
    
    /* Unregister service */
    result = BAUnregisterService(TEST_SERVICE_NAME);
    if (result != BA_OK) {
        BAFreeTXTRecord(txt);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    BAFreeTXTRecord(txt);
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test service enumeration */
static LONG testServiceEnumeration(struct TestState *state)
{
    LONG result;
    struct BAStringList *types;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Register test service */
    result = BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 
                             TEST_SERVICE_PORT, NULL);
    if (result != BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Wait for registration */
    Delay(50);
    
    /* Enumerate service types */
    types = BAEnumerateServiceTypes();
    if (!types) {
        BAUnregisterService(TEST_SERVICE_NAME);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Print service types */
    struct BAStringList *current;
    for (current = types; current; current = current->next) {
        printf("Service type: %s\n", current->string);
    }
    
    /* Unregister service */
    result = BAUnregisterService(TEST_SERVICE_NAME);
    if (result != BA_OK) {
        BAFreeStringList(types);
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    BAFreeStringList(types);
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
}

/* Test error handling */
static LONG testErrorHandling(struct TestState *state)
{
    LONG result;
    
    /* Open library */
    state->BonAmiBase = OpenLibrary("bonami.library", 0);
    if (!state->BonAmiBase) {
        return RETURN_ERROR;
    }
    
    /* Test invalid service name */
    result = BARegisterService("", TEST_SERVICE_TYPE, TEST_SERVICE_PORT, NULL);
    if (result == BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Test invalid service type */
    result = BARegisterService(TEST_SERVICE_NAME, "", TEST_SERVICE_PORT, NULL);
    if (result == BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Test invalid port */
    result = BARegisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE, 0, NULL);
    if (result == BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Test invalid TXT record */
    result = BAAddTXTRecord(NULL, "key", "value");
    if (result == BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Test invalid interface */
    result = BASetPreferredInterface("");
    if (result == BA_OK) {
        CloseLibrary(state->BonAmiBase);
        return RETURN_ERROR;
    }
    
    /* Cleanup */
    CloseLibrary(state->BonAmiBase);
    state->BonAmiBase = NULL;
    
    return RETURN_OK;
} 