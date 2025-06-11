# BonAmi Developer Guide

## Introduction

BonAmi is an mDNS (multicast DNS) and DNS-SD (DNS Service Discovery) implementation for AmigaOS, designed to provide service discovery capabilities similar to Apple's Bonjour. This guide will help you understand how to use the BonAmi library in your applications.

## Features

- mDNS protocol implementation (RFC 6762)
- DNS-SD support (RFC 6763)
- Service registration and discovery
- Service conflict resolution
- Per-interface service management
- DNS record caching
- Host name management
- IPv4 support (local network)

## Getting Started

### Including the Library

```c
#include <proto/bonami.h>
```

### Initializing the Library

```c
struct Library *BonamiBase = OpenLibrary("bonami.library", 0);
if (!BonamiBase) {
    /* Handle error */
}
```

## Service Registration

### Registering a Service

```c
struct BAService service;
memset(&service, 0, sizeof(service));
strncpy(service.name, "My Service", BA_MAX_NAME_LEN - 1);
strncpy(service.type, "_http._tcp.local", BA_MAX_SERVICE_LEN - 1);
service.port = 80;
service.txt = NULL;  /* Optional TXT record */

LONG result = BARegisterService(&service);
if (result != BA_OK) {
    /* Handle error */
}
```

The registration process follows these steps:
1. Service name conflict probing
2. Service announcement
3. Active service state

### Unregistering a Service

```c
LONG result = BAUnregisterService("My Service", "_http._tcp.local");
if (result != BA_OK) {
    /* Handle error */
}
```

## Service Discovery

### Starting Discovery

```c
struct BADiscovery discovery;
memset(&discovery, 0, sizeof(discovery));
strncpy(discovery.type, "_http._tcp.local", BA_MAX_SERVICE_LEN - 1);
discovery.callback = myCallback;
discovery.userData = NULL;

LONG result = BAStartDiscovery(&discovery);
if (result != BA_OK) {
    /* Handle error */
}
```

### Discovery Callback

```c
void myCallback(const struct BAService *service, void *userData)
{
    /* Handle discovered service */
    printf("Found service: %s\n", service->name);
    printf("Type: %s\n", service->type);
    printf("Port: %ld\n", service->port);
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
LONG result = BAResolveService("My Service", "_http._tcp.local", &service);
if (result != BA_OK) {
    /* Handle error */
}
```

## Service Type Enumeration

### Enumerating Service Types

```c
struct List types;
NewList(&types);
LONG result = BAEnumerateServiceTypes(&types);
if (result != BA_OK) {
    /* Handle error */
}
```

## DNS Queries

### Performing DNS Queries

```c
void *result;
LONG resultlen = 1024;
result = AllocMem(resultlen, MEMF_CLEAR);
if (result) {
    LONG count = BAQueryRecord("example.local", DNS_TYPE_A, DNS_CLASS_IN, result, resultlen);
    if (count < 0) {
        /* Handle error */
    }
    FreeMem(result, resultlen);
}
```

## Error Handling

BonAmi uses the following error codes:

- `BA_OK`: Operation successful
- `BA_BADPARAM`: Invalid parameter
- `BA_NOMEM`: Out of memory
- `BA_TIMEOUT`: Operation timed out
- `BA_DUPLICATE`: Service already registered
- `BA_NOTFOUND`: Service not found
- `BA_BADTYPE`: Invalid service type
- `BA_BADNAME`: Invalid service name
- `BA_BADPORT`: Invalid port number
- `BA_BADTXT`: Invalid TXT record
- `BA_BADQUERY`: Invalid DNS query
- `BA_BADRESPONSE`: Invalid DNS response
- `BA_NETWORK`: Network error
- `BA_NOTREADY`: Network not ready
- `BA_BUSY`: Operation in progress
- `BA_CANCELLED`: Operation cancelled

## Best Practices

1. **Service Names**
   - Use unique, descriptive names
   - Follow DNS naming conventions
   - Avoid special characters

2. **Service Types**
   - Use standard service types when available
   - Follow the `_service._tcp.local` format
   - Register new types with IANA

3. **Error Handling**
   - Always check return values
   - Handle all possible error conditions
   - Clean up resources on error

4. **Resource Management**
   - Unregister services when done
   - Stop discovery when no longer needed
   - Free allocated memory

5. **Network Considerations**
   - Handle network state changes
   - Consider service conflicts
   - Monitor interface status

## Complete Example

Here's a complete example of a service registration and discovery:

```c
#include <proto/bonami.h>
#include <stdio.h>

void serviceCallback(const struct BAService *service, void *userData)
{
    printf("Found service: %s\n", service->name);
    printf("Type: %s\n", service->type);
    printf("Port: %ld\n", service->port);
}

int main(void)
{
    struct Library *BonamiBase = OpenLibrary("bonami.library", 0);
    if (!BonamiBase) {
        printf("Failed to open bonami.library\n");
        return 1;
    }
    
    /* Register a service */
    struct BAService service;
    memset(&service, 0, sizeof(service));
    strncpy(service.name, "My Web Server", BA_MAX_NAME_LEN - 1);
    strncpy(service.type, "_http._tcp.local", BA_MAX_SERVICE_LEN - 1);
    service.port = 80;
    service.txt = NULL;
    
    LONG result = BARegisterService(&service);
    if (result != BA_OK) {
        printf("Failed to register service: %ld\n", result);
        CloseLibrary(BonamiBase);
        return 1;
    }
    
    /* Start discovery */
    struct BADiscovery discovery;
    memset(&discovery, 0, sizeof(discovery));
    strncpy(discovery.type, "_http._tcp.local", BA_MAX_SERVICE_LEN - 1);
    discovery.callback = serviceCallback;
    discovery.userData = NULL;
    
    result = BAStartDiscovery(&discovery);
    if (result != BA_OK) {
        printf("Failed to start discovery: %ld\n", result);
        BAUnregisterService(service.name, service.type);
        CloseLibrary(BonamiBase);
        return 1;
    }
    
    /* Wait for discoveries */
    printf("Waiting for services...\n");
    Delay(5000);  /* Wait 5 seconds */
    
    /* Cleanup */
    BAStopDiscovery(&discovery);
    BAUnregisterService(service.name, service.type);
    CloseLibrary(BonamiBase);
    
    return 0;
}
```

## Advanced Features

### Service Conflict Resolution

BonAmi implements proper service conflict resolution:
1. Probing phase to check for conflicts
2. Multiple probe attempts
3. Automatic conflict detection
4. Service state management

### TTL Management

The daemon handles TTL (Time To Live) properly:
1. Service announcement phase
2. Multiple announcement attempts
3. Record refreshing
4. Cache management

### Interface Management

BonAmi supports multiple network interfaces:
1. Per-interface service tracking
2. Link-local detection
3. Interface state monitoring
4. Automatic service updates

### DNS Record Caching

The daemon implements DNS record caching:
1. TTL-based expiration
2. Automatic cache cleanup
3. Record refreshing
4. Memory-efficient storage

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

### Debugging

Enable debug logging by setting the log level in the configuration file:
```
SYS:Utilities/BonAmi/config
3  # LOG_DEBUG level
```

## Contributing

We welcome contributions to BonAmi. Please follow these guidelines:
1. Follow the existing code style
2. Add proper error handling
3. Update documentation
4. Add tests when possible

## License

BonAmi is released under the MIT License. See the LICENSE file for details. 