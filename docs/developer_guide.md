# BonAmi Developer Guide

## Introduction

BonAmi is an mDNS (multicast DNS) and DNS-SD (DNS Service Discovery) implementation for AmigaOS 3.x and 4.x, designed to provide service discovery capabilities similar to Apple's Bonjour. This guide will help you understand how to use the BonAmi library in your applications.

## Architecture

BonAmi follows a client-server architecture:

- **Library (`bonami.library`)**: A thin client library that provides a simple API for applications to interact with the mDNS daemon. The library is stateless and handles message passing to the daemon.

- **Daemon (`Bonami`)**: A background process that manages all mDNS operations, including:
  - Service registration and discovery
  - Network interface management
  - State management
  - Resource management
  - Memory pools for long-lived objects

## Features

- Service registration and discovery
- Support for TXT records
- Automatic service conflict resolution
- Service monitoring and updates
- Thread-safe operations
- Memory pool management
- AmigaOS 3.x and 4.x support

## Getting Started

### Including the Library

```c
#include <proto/bonami.h>
```

### Initializing the Library

```c
struct Library *BonamiBase = OpenLibrary("bonami.library", 40);  /* Version 40 for AmigaOS 3.1 */
if (!BonamiBase) {
    /* Handle error */
}

#ifdef __amigaos4__
struct BonAmiIFace *IBonAmi = (struct BonAmiIFace *)GetInterface(BonamiBase, "main", 1, NULL);
if (!IBonAmi) {
    /* Handle error */
}
#endif
```

## Service Registration

### Registering a Service

```c
struct BAService service = {
    .name = "My Service",
    .type = "_http._tcp",
    .port = 80,
    .txt = "path=/"
};

LONG result = BARegisterService(&service);
if (result != BA_OK) {
    /* Handle error */
}
```

### Unregistering a Service

```c
LONG result = BAUnregisterService("My Service", "_http._tcp");
if (result != BA_OK) {
    /* Handle error */
}
```

## Service Discovery

### Starting Discovery

```c
struct BADiscovery discovery = {
    .type = "_http._tcp",
    .callback = myCallback,
    .userData = NULL
};

LONG result = BAStartDiscovery(&discovery);
if (result != BA_OK) {
    /* Handle error */
}
```

### Discovery Callback

```c
void myCallback(struct BAService *service, APTR userData)
{
    /* Handle discovered service */
    printf("Found service: %s\n", service->name);
    printf("Type: %s\n", service->type);
    printf("Port: %d\n", service->port);
    printf("TXT: %s\n", service->txt);
}
```

### Stopping Discovery

```c
LONG result = BAStopDiscovery(&discovery);
if (result != BA_OK) {
    /* Handle error */
}
```

## Service Resolution

### Resolving a Service

```c
struct BAService service;
LONG result = BAResolveService("My Service", "_http._tcp", &service);
if (result != BA_OK) {
    /* Handle error */
}
```

## TXT Records

### Creating TXT Records

```c
STRPTR txt = BACreateTXTRecord("path", "/");
if (!txt) {
    /* Handle error */
}

/* Use TXT record */
struct BAService service = {
    .name = "My Service",
    .type = "_http._tcp",
    .port = 80,
    .txt = txt
};

/* Free TXT record when done */
BAFreeTXTRecord(txt);
```

## Error Handling

BonAmi uses the following error codes:

- `BA_OK`: Operation successful
- `BA_NOMEM`: Out of memory
- `BA_INVALID`: Invalid parameter
- `BA_DUPLICATE`: Service already registered
- `BA_NOTFOUND`: Service not found
- `BA_TIMEOUT`: Operation timed out
- `BA_NETWORK`: Network error
- `BA_VERSION`: Version mismatch

## Best Practices

1. **Service Names**
   - Use unique, descriptive names
   - Follow DNS naming conventions
   - Avoid special characters

2. **Service Types**
   - Use standard service types when available
   - Follow the `_service._tcp` format
   - Register new types with IANA

3. **Error Handling**
   - Always check return values
   - Handle all possible error conditions
   - Clean up resources on error

4. **Resource Management**
   - Unregister services when done
   - Stop discovery when no longer needed
   - Free allocated memory
   - Close library properly

5. **AmigaOS 4.x Support**
   - Use interface-based calls
   - Handle interface versioning
   - Clean up interfaces properly

## Complete Example

Here's a complete example of a service registration and discovery:

```c
#include <proto/bonami.h>
#include <stdio.h>

void serviceCallback(struct BAService *service, APTR userData)
{
    printf("Found service: %s\n", service->name);
    printf("Type: %s\n", service->type);
    printf("Port: %d\n", service->port);
    printf("TXT: %s\n", service->txt);
}

int main(void)
{
    struct Library *BonamiBase = OpenLibrary("bonami.library", 40);
    if (!BonamiBase) {
        printf("Failed to open bonami.library\n");
        return 1;
    }
    
#ifdef __amigaos4__
    struct BonAmiIFace *IBonAmi = (struct BonAmiIFace *)GetInterface(BonamiBase, "main", 1, NULL);
    if (!IBonAmi) {
        printf("Failed to get interface\n");
        CloseLibrary(BonamiBase);
        return 1;
    }
#endif
    
    /* Register a service */
    struct BAService service = {
        .name = "My Web Server",
        .type = "_http._tcp",
        .port = 80,
        .txt = "path=/"
    };
    
    LONG result = BARegisterService(&service);
    if (result != BA_OK) {
        printf("Failed to register service: %ld\n", result);
        goto cleanup;
    }
    
    /* Start discovery */
    struct BADiscovery discovery = {
        .type = "_http._tcp",
        .callback = serviceCallback,
        .userData = NULL
    };
    
    result = BAStartDiscovery(&discovery);
    if (result != BA_OK) {
        printf("Failed to start discovery: %ld\n", result);
        BAUnregisterService(service.name, service.type);
        goto cleanup;
    }
    
    /* Wait for discoveries */
    printf("Waiting for services...\n");
    Delay(5000);  /* Wait 5 seconds */
    
    /* Cleanup */
    BAStopDiscovery(&discovery);
    BAUnregisterService(service.name, service.type);
    
cleanup:
#ifdef __amigaos4__
    DropInterface((struct Interface *)IBonAmi);
#endif
    CloseLibrary(BonamiBase);
    
    return 0;
}
```

## Troubleshooting

### Common Issues

1. **Service Registration Fails**
   - Check for name conflicts
   - Verify network connectivity
   - Check interface status
   - Verify service type format

2. **Discovery Not Working**
   - Verify network connectivity
   - Check interface status
   - Verify service type
   - Check callback function

3. **Network Issues**
   - Check interface status
   - Verify multicast support
   - Check firewall settings
   - Verify network configuration

## Contributing

We welcome contributions to BonAmi. Please follow these guidelines:
1. Follow the existing code style
2. Add proper error handling
3. Update documentation
4. Add tests when possible

## License

BonAmi is released under the MIT License. See the LICENSE file for details. 