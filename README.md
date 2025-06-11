# BonAmi mDNS Library

A lightweight mDNS (multicast DNS) library for AmigaOS 3.x and 4.x, providing service discovery and registration capabilities.

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

## Building

### Requirements

- AmigaOS 3.1 or later
- SAS/C or GCC compiler
- Roadshow TCP/IP stack

### Building for AmigaOS 3.x

```bash
smake
```

### Building for AmigaOS 4.x

```bash
make
```

## Usage

### Library API

The library provides a simple API for applications to interact with the mDNS daemon:

```c
#include <proto/bonami.h>

// Register a service
struct BAService service = {
    .name = "My Service",
    .type = "_http._tcp",
    .port = 80,
    .txt = "path=/"
};

LONG result = BARegisterService(&service);

// Discover services
struct BAService *services;
ULONG count;
result = BADiscoverServices("_http._tcp", &services, &count);

// Monitor services
result = BAMonitorServices("_http._tcp", myCallback, NULL);

// Unregister a service
result = BAUnregisterService("My Service", "_http._tcp");
```

### Daemon

The daemon must be running for the library to work. It can be started from the startup sequence:

```
C:bonamid
```

## Examples

### Service Registration

```c
#include <proto/bonami.h>

int main(int argc, char **argv)
{
    struct BAService service = {
        .name = "My Service",
        .type = "_http._tcp",
        .port = 80,
        .txt = "path=/"
    };

    LONG result = BARegisterService(&service);
    if (result != BA_OK) {
        printf("Failed to register service: %ld\n", result);
        return 1;
    }

    return 0;
}
```

### Service Discovery

```c
#include <proto/bonami.h>

int main(int argc, char **argv)
{
    struct BAService *services;
    ULONG count;
    LONG result = BADiscoverServices("_http._tcp", &services, &count);
    if (result != BA_OK) {
        printf("Failed to discover services: %ld\n", result);
        return 1;
    }

    for (ULONG i = 0; i < count; i++) {
        printf("Service: %s\n", services[i].name);
        printf("Host: %s\n", services[i].host);
        printf("Port: %d\n", services[i].port);
        printf("TXT: %s\n", services[i].txt);
    }

    return 0;
}
```

## Error Codes

- `BA_OK`: Operation successful
- `BA_NOMEM`: Out of memory
- `BA_INVALID`: Invalid parameter
- `BA_DUPLICATE`: Service already registered
- `BA_NOTFOUND`: Service not found
- `BA_TIMEOUT`: Operation timed out
- `BA_NETWORK`: Network error
- `BA_VERSION`: Version mismatch

## Thread Safety

The library is designed to be thread-safe and reentrant. The daemon uses semaphores to protect shared resources and ensure thread-safe operations.

## Memory Management

The daemon uses memory pools for long-lived objects, while the library uses standard memory allocation for ephemeral objects like messages.

## Version History

- 40.0: Initial release
  - Basic service registration and discovery
  - TXT record support
  - AmigaOS 3.x and 4.x support
  - Thread-safe operations
  - Memory pool management

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
