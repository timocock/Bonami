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
struct BonamiService service;
service.name = "My Service";
service.type = "_http._tcp.local";
service.port = 80;
service.txt = NULL;  /* Optional TXT record */

LONG result = BonamiRegisterService(&service);
if (result != BONAMI_OK) {
    /* Handle error */
}
```

The registration process follows these steps:
1. Service name conflict probing
2. Service announcement
3. Active service state

### Unregistering a Service

```c
LONG result = BonamiUnregisterService("My Service", "_http._tcp.local");
if (result != BONAMI_OK) {
    /* Handle error */
}
```

## Service Discovery

### Starting Discovery

```c
struct BonamiDiscovery discovery;
discovery.type = "_http._tcp.local";
discovery.callback = myCallback;
discovery.userData = NULL;

LONG result = BonamiStartDiscovery(&discovery);
if (result != BONAMI_OK) {
    /* Handle error */
}
```

### Discovery Callback

```c
void myCallback(const struct BonamiService *service, void *userData)
{
    /* Handle discovered service */
    printf("Found service: %s\n", service->name);
    printf("Type: %s\n", service->type);
    printf("Port: %ld\n", service->port);
}
```

### Stopping Discovery

```c
LONG result = BonamiStopDiscovery("_http._tcp.local");
if (result != BONAMI_OK) {
    /* Handle error */
}
```

## Service Resolution

### Resolving a Service

```c
struct BonamiService service;
LONG result = BonamiResolveService("My Service", "_http._tcp.local", &service);
if (result != BONAMI_OK) {
    /* Handle error */
}
```

## Service Type Enumeration

### Enumerating Service Types

```c
struct BonamiServiceType types[10];
LONG count = BonamiEnumerateServiceTypes(types, 10);
if (count < 0) {
    /* Handle error */
}
```

## DNS Queries

### Performing DNS Queries

```c
struct DNSRecord records[10];
LONG count = BonamiQueryDNS("example.local", DNS_TYPE_A, DNS_CLASS_IN, records, 10);
if (count < 0) {
    /* Handle error */
}
```

## Error Handling

BonAmi uses the following error codes:

- `BONAMI_OK`: Operation successful
- `BONAMI_ERROR`: General error
- `BONAMI_NOMEM`: Out of memory
- `BONAMI_BADPARAM`: Invalid parameter
- `BONAMI_BADNAME`: Invalid service name
- `BONAMI_BADTYPE`: Invalid service type
- `BONAMI_BADPORT`: Invalid port number
- `BONAMI_CONFLICT`: Service name conflict
- `BONAMI_NETWORK`: Network error
- `BONAMI_TIMEOUT`: Operation timed out
- `BONAMI_BADQUERY`: Invalid DNS query
- `BONAMI_BADRESPONSE`: Invalid DNS response

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

void serviceCallback(const struct BonamiService *service, void *userData)
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
    struct BonamiService service;
    service.name = "My Web Server";
    service.type = "_http._tcp.local";
    service.port = 80;
    service.txt = NULL;
    
    LONG result = BonamiRegisterService(&service);
    if (result != BONAMI_OK) {
        printf("Failed to register service: %ld\n", result);
        CloseLibrary(BonamiBase);
        return 1;
    }
    
    /* Start discovery */
    struct BonamiDiscovery discovery;
    discovery.type = "_http._tcp.local";
    discovery.callback = serviceCallback;
    discovery.userData = NULL;
    
    result = BonamiStartDiscovery(&discovery);
    if (result != BONAMI_OK) {
        printf("Failed to start discovery: %ld\n", result);
        BonamiUnregisterService(service.name, service.type);
        CloseLibrary(BonamiBase);
        return 1;
    }
    
    /* Wait for discoveries */
    printf("Waiting for services...\n");
    Delay(5000);  /* Wait 5 seconds */
    
    /* Cleanup */
    BonamiStopDiscovery(discovery.type);
    BonamiUnregisterService(service.name, service.type);
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
ENV:Bonami/config
2  # LOG_DEBUG level
```

## Contributing

We welcome contributions to BonAmi. Please follow these guidelines:
1. Follow the existing code style
2. Add proper error handling
3. Update documentation
4. Add tests when possible

## License

BonAmi is released under the MIT License. See the LICENSE file for details. 