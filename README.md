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

### Command Line Tools

#### BonAmi Daemon (`Bonami`)

The daemon must be running for the library to work. It can be started with the following options:

```
Bonami [LOG/S] [LOGFILE/F] [DEBUG/S]
```

Where:
- `LOG/S`: Enable logging to console
- `LOGFILE/F`: Log file path
- `DEBUG/S`: Enable debug output

Example:
```
Bonami LOG LOGFILE=RAM:Bonami.log DEBUG
```

#### BonAmi Control (`BACtl`)

The control utility provides commands for managing mDNS services:

```
BACtl <command> [options]
```

Commands:

1. **Discover Services**
```
BACtl discover TYPE/K [NAME/K] [FILTER/K] [TIMEOUT/N]
```
- `TYPE`: Service type (e.g., "_http._tcp")
- `NAME`: Optional service name filter
- `FILTER`: Optional TXT record filter
- `TIMEOUT`: Optional timeout in seconds (default: 5)

2. **Register Service**
```
BACtl register NAME/K TYPE/K PORT/N [TXT/M]
```
- `NAME`: Service name
- `TYPE`: Service type (e.g., "_http._tcp")
- `PORT`: Service port number
- `TXT`: Optional TXT record (can be specified multiple times)

3. **Unregister Service**
```
BACtl unregister NAME/K TYPE/K
```
- `NAME`: Service name
- `TYPE`: Service type

4. **List Services**
```
BACtl list TYPE/K
```
- `TYPE`: Service type to list

5. **Resolve Service**
```
BACtl resolve NAME/K TYPE/K
```
- `NAME`: Service name
- `TYPE`: Service type

6. **Monitor Service**
```
BACtl monitor NAME/K TYPE/K [INTERVAL/N] [NOTIFY/S]
```
- `NAME`: Service name
- `TYPE`: Service type
- `INTERVAL`: Optional check interval in seconds (default: 30)
- `NOTIFY/S`: Enable desktop notifications

7. **Status**
```
BACtl status
```
Shows daemon status including:
- Number of registered services
- Number of active discoveries
- Number of monitors
- Interface status

Examples:
```
# Discover all HTTP services
BACtl discover TYPE=_http._tcp

# Register a web server
BACtl register NAME=MyWebServer TYPE=_http._tcp PORT=80 TXT=path=/ TXT=version=1.0

# Monitor a service
BACtl monitor NAME=MyWebServer TYPE=_http._tcp INTERVAL=60 NOTIFY

# Check daemon status
BACtl status
```

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

## Examples

### Advertising a Service from Amiga

This example shows how to advertise a service running on your Amiga. Let's say you have a web server running on port 8080:

```c
#include <proto/bonami.h>
#include <proto/exec.h>
#include <proto/dos.h>

int main(int argc, char **argv)
{
    // Open the library
    struct Library *BonAmiBase = BAOpenLibrary(40, NULL);
    if (!BonAmiBase) {
        Printf("Failed to open bonami.library\n");
        return RETURN_FAIL;
    }

    // Create a service structure
    struct BAService service = {
        .name = "AmigaWebServer",    // Your service name
        .type = "_http._tcp",        // HTTP service type
        .port = 8080,                // Your web server port
        .txt = "path=/",             // Optional TXT record
    };

    // Register the service
    LONG result = BARegisterService(&service);
    if (result != BA_OK) {
        Printf("Failed to register service: %ld\n", result);
        BACloseLibrary(BonAmiBase);
        return RETURN_FAIL;
    }

    Printf("Service registered successfully!\n");
    Printf("Other devices can now discover 'AmigaWebServer' on the network\n");

    // Keep the service registered
    Printf("Press Ctrl-C to unregister and exit\n");
    Wait(SIGBREAKF_CTRL_C);

    // Unregister the service before exiting
    BAUnregisterService(service.name, service.type);
    BACloseLibrary(BonAmiBase);

    return RETURN_OK;
}
```

You can also use the command line tool to register the service:

```bash
# Register the web server
BACtl register NAME=AmigaWebServer TYPE=_http._tcp PORT=8080 TXT=path=/

# Check if it's registered
BACtl list TYPE=_http._tcp

# When done, unregister it
BACtl unregister NAME=AmigaWebServer TYPE=_http._tcp
```

This will make your Amiga's web server discoverable by other devices on the network. They can find it by searching for "_http._tcp" services, and they'll see "AmigaWebServer" in their list of available web servers.

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

TBD

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
