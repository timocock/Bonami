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
#define TEST_TIMEOUT 5

/* Test state */
struct TestState {
    struct Library *BonAmiBase;
    #ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi;
    #endif
    BOOL success;
};

/* Forward declarations */
static LONG runTest(const char *name, LONG (*testFunc)(struct TestState *));
static LONG testLibraryOpen(struct TestState *state);
static LONG testServiceRegistration(struct TestState *state);
static LONG testServiceDiscovery(struct TestState *state);
static LONG testErrorHandling(struct TestState *state);

/* Discovery callback */
static void discoveryCallback(struct BAService *service, APTR userData)
{
    printf("Found service: %s\n", service->name);
    printf("  Type: %s\n", service->type);
    printf("  Port: %d\n", service->port);
    printf("  TXT: %s\n", service->txt ? service->txt : "none");
    printf("\n");
}

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
    
    if (runTest("Error Handling", testErrorHandling) != RETURN_OK) {
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
    struct TestState state;
    memset(&state, 0, sizeof(state));
    
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
    
    /* Register service */
    struct BAService service = {
        .name = TEST_SERVICE_NAME,
        .type = TEST_SERVICE_TYPE,
        .port = TEST_SERVICE_PORT,
        .txt = "test=true"
    };
    
    #ifdef __amigaos4__
    result = state->IBonAmi->BARegisterService(&service);
    #else
    result = BARegisterService(&service);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Wait for registration */
    Delay(50);
    
    /* Unregister service */
    #ifdef __amigaos4__
    result = state->IBonAmi->BAUnregisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE);
    #else
    result = BAUnregisterService(TEST_SERVICE_NAME, TEST_SERVICE_TYPE);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Cleanup */
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

/* Test service discovery */
static LONG testServiceDiscovery(struct TestState *state)
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
    
    /* Start discovery */
    struct BADiscovery discovery = {
        .type = TEST_SERVICE_TYPE,
        .callback = discoveryCallback,
        .userData = NULL
    };
    
    #ifdef __amigaos4__
    result = state->IBonAmi->BAStartDiscovery(&discovery);
    #else
    result = BAStartDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Wait for discovery */
    Delay(50);
    
    /* Stop discovery */
    #ifdef __amigaos4__
    result = state->IBonAmi->BAStopDiscovery(&discovery);
    #else
    result = BAStopDiscovery(&discovery);
    #endif
    if (result != BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Cleanup */
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

/* Test error handling */
static LONG testErrorHandling(struct TestState *state)
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
    
    /* Test invalid service name */
    struct BAService service = {
        .name = "",
        .type = TEST_SERVICE_TYPE,
        .port = TEST_SERVICE_PORT
    };
    
    #ifdef __amigaos4__
    result = state->IBonAmi->BARegisterService(&service);
    #else
    result = BARegisterService(&service);
    #endif
    if (result == BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Test invalid service type */
    service.name = TEST_SERVICE_NAME;
    service.type = "";
    
    #ifdef __amigaos4__
    result = state->IBonAmi->BARegisterService(&service);
    #else
    result = BARegisterService(&service);
    #endif
    if (result == BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Test invalid port */
    service.type = TEST_SERVICE_TYPE;
    service.port = 0;
    
    #ifdef __amigaos4__
    result = state->IBonAmi->BARegisterService(&service);
    #else
    result = BARegisterService(&service);
    #endif
    if (result == BA_OK) {
        #ifdef __amigaos4__
        IExec->DropInterface((struct Interface *)state->IBonAmi);
        IExec->CloseLibrary(state->BonAmiBase);
        #else
        CloseLibrary(state->BonAmiBase);
        #endif
        return RETURN_ERROR;
    }
    
    /* Cleanup */
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
} 