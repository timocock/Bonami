# BonAmi Developer Guide

This guide explains how to use the BonAmi library to implement mDNS and DNS-SD functionality in your AmigaOS applications.

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Service Registration](#service-registration)
4. [Service Discovery](#service-discovery)
5. [Service Resolution](#service-resolution)
6. [Service Type Enumeration](#service-type-enumeration)
7. [Arbitrary DNS Queries](#arbitrary-dns-queries)
8. [Asynchronous Notifications](#asynchronous-notifications)
9. [Updating Services](#updating-services)
10. [Best Practices](#best-practices)
11. [Error Handling](#error-handling)
12. [Examples](#examples)

## Introduction

BonAmi provides a C API for implementing mDNS (multicast DNS) and DNS-SD (DNS Service Discovery) on AmigaOS. It allows your applications to:
- Advertise services on the local network
- Discover services advertised by other devices
- Resolve service details
- Receive notifications about service changes

## Getting Started

### Including the Header

```c
#include <proto/bonami.h>
```

### Opening the Library

```c
struct Library *BonamiBase = OpenLibrary("bonami.library", 0);
if (!BonamiBase) {
    // Handle error
}
```

## Service Registration

To advertise a service on the network:

```c
struct BonamiService service;
strcpy(service.name, "MyService");
strcpy(service.type, "_http._tcp");
service.port = 80;
strcpy(service.txt, "path=/");
service.ttl = 120; // 2 minutes

LONG result = BonamiRegisterService(&service);
if (result != BONAMI_OK) {
    // Handle error
}
```

## Service Discovery

To discover services of a specific type:

```c
struct BonamiDiscovery discovery;
strcpy(discovery.type, "_http._tcp");
discovery.services = NULL;
discovery.lock = NULL;
discovery.callback = NULL;

LONG result = BonamiStartDiscovery(&discovery);
if (result != BONAMI_OK) {
    // Handle error
}

// Later, stop discovery
BonamiStopDiscovery(&discovery);
```

## Service Resolution

To get details about a specific service:

```c
struct BonamiServiceInfo info;
LONG result = BonamiGetServiceInfo(&info, "MyService", "_http._tcp");
if (result == BONAMI_OK) {
    // Use info.port, info.ip, info.txt, etc.
}
```

## Service Type Enumeration

To list all service types currently advertised:

```c
struct List types;
NewList(&types);

LONG result = BonamiEnumerateServiceTypes(&types);
if (result == BONAMI_OK) {
    // Iterate through types
    struct Node *node;
    for (node = types.lh_Head; node->ln_Succ; node = node->ln_Succ) {
        // Process each service type
    }
}
```

## Arbitrary DNS Queries

For advanced use cases, you can query arbitrary DNS records:

```c
void *result = AllocMem(1024, MEMF_CLEAR);
if (result) {
    LONG queryResult = BonamiQueryRecord("example.local", DNS_TYPE_A, DNS_CLASS_IN, result, 1024);
    if (queryResult == BONAMI_OK) {
        // Process result
    }
    FreeMem(result, 1024);
}
```

## Asynchronous Notifications

To receive notifications about service changes:

```c
void serviceCallback(struct BonamiServiceInfo *info, int event) {
    switch (event) {
        case BONAMI_EVENT_ADDED:
            // Service appeared
            break;
        case BONAMI_EVENT_REMOVED:
            // Service disappeared
            break;
        case BONAMI_EVENT_UPDATED:
            // Service updated
            break;
    }
}

struct BonamiDiscovery discovery;
discovery.callback = serviceCallback;
BonamiStartDiscovery(&discovery);
```

## Updating Services

To update a service's TXT record:

```c
LONG result = BonamiUpdateServiceTXT("MyService", "_http._tcp", "path=/new");
if (result != BONAMI_OK) {
    // Handle error
}
```

To update a service's details:

```c
struct BonamiService service;
strcpy(service.name, "MyService");
strcpy(service.type, "_http._tcp");
service.port = 8080;
strcpy(service.txt, "path=/updated");
service.ttl = 300;

LONG result = BonamiUpdateService(&service);
if (result != BONAMI_OK) {
    // Handle error
}
```

## Best Practices

1. **Error Handling**: Always check return values and handle errors appropriately.
2. **Resource Management**: Clean up resources (stop discovery, unregister services) when done.
3. **Thread Safety**: Use the provided semaphore for thread-safe operations.
4. **Memory Management**: Use static buffers where possible to avoid memory fragmentation.

## Error Handling

Common error codes:
- `BONAMI_OK`: Operation successful
- `BONAMI_ERROR`: General error
- `BONAMI_NOMEM`: Out of memory
- `BONAMI_TIMEOUT`: Operation timed out
- `BONAMI_BADPARAM`: Invalid parameters

## Examples

### Complete Service Registration Example

```c
#include <proto/bonami.h>
#include <proto/exec.h>
#include <proto/dos.h>

int main() {
    struct Library *BonamiBase = OpenLibrary("bonami.library", 0);
    if (!BonamiBase) {
        Printf("Failed to open bonami.library\n");
        return 1;
    }

    struct BonamiService service;
    strcpy(service.name, "MyWebServer");
    strcpy(service.type, "_http._tcp");
    service.port = 80;
    strcpy(service.txt, "path=/");
    service.ttl = 120;

    LONG result = BonamiRegisterService(&service);
    if (result != BONAMI_OK) {
        Printf("Failed to register service: %ld\n", result);
    } else {
        Printf("Service registered successfully\n");
    }

    CloseLibrary(BonamiBase);
    return 0;
}
```

### Complete Service Discovery Example

```c
#include <proto/bonami.h>
#include <proto/exec.h>
#include <proto/dos.h>

void serviceCallback(struct BonamiServiceInfo *info, int event) {
    switch (event) {
        case BONAMI_EVENT_ADDED:
            Printf("Service added: %s\n", info->name);
            break;
        case BONAMI_EVENT_REMOVED:
            Printf("Service removed: %s\n", info->name);
            break;
        case BONAMI_EVENT_UPDATED:
            Printf("Service updated: %s\n", info->name);
            break;
    }
}

int main() {
    struct Library *BonamiBase = OpenLibrary("bonami.library", 0);
    if (!BonamiBase) {
        Printf("Failed to open bonami.library\n");
        return 1;
    }

    struct BonamiDiscovery discovery;
    strcpy(discovery.type, "_http._tcp");
    discovery.services = NULL;
    discovery.lock = NULL;
    discovery.callback = serviceCallback;

    LONG result = BonamiStartDiscovery(&discovery);
    if (result != BONAMI_OK) {
        Printf("Failed to start discovery: %ld\n", result);
    } else {
        Printf("Discovery started. Press Ctrl+C to stop.\n");
        Wait(SIGBREAKF_CTRL_C);
        BonamiStopDiscovery(&discovery);
    }

    CloseLibrary(BonamiBase);
    return 0;
}
```

## Conclusion

This guide covers the basic usage of the BonAmi library. For more advanced features and detailed API documentation, refer to the header file (`bonami.h`) and the library's function description file (`bonami_lib.fd`).

Happy coding! 