# BonAmi - mDNS Implementation for AmigaOS

BonAmi is an mDNS (multicast DNS) implementation for AmigaOS, designed to work with the Roadshow TCP/IP stack. It provides functionality similar to Apple's Bonjour, allowing Amiga computers to discover and advertise services on their local network.

## Architecture Overview

### Core Components

1. **mDNS Daemon (bonami)**
   - Runs as a background process
   - Handles multicast DNS queries and responses
   - Manages service registration and discovery
   - Uses Roadshow's bsdsocket.library for network communication
   - Implements RFC 6762 (mDNS) and RFC 6763 (DNS-SD)
   - Monitors network interface status
   - Implements service conflict resolution
   - Manages DNS record caching
   - Handles TTL management
   - Supports multiple network interfaces

2. **Library Interface (bonami.library)**
   - Provides API for applications to register and discover services
   - Handles communication with the daemon via message passing
   - Implements the mDNS protocol according to RFC 6762
   - Supports both synchronous and asynchronous operations
   - Provides callback mechanism for service discovery
   - Manages service state and updates

3. **Command Line Tools**
   - `bonami-register`: Register services
   - `bonami-browse`: Browse available services
   - `bonami-query`: Query specific service types
   - `bonami-unregister`: Remove service registrations

### Technical Constraints

- IPv4 only (no IPv6 support)
- C89 compatible code
- Uses Roadshow's bsdsocket.library
- Limited to AmigaOS system calls and APIs
- Memory efficient design for classic Amiga hardware
- Compatible with AmigaOS 3.x and higher

### Protocol Implementation

1. **Multicast Communication**
   - Uses UDP port 5353
   - Multicast address: 224.0.0.251
   - TTL: 255 (local network only)
   - Implements proper multicast group management
   - Handles network interface changes

2. **Service Discovery**
   - Implements DNS-SD (DNS Service Discovery)
   - Supports service type enumeration
   - Handles service instance resolution
   - Implements service browsing and querying
   - Supports service registration and unregistration
   - Implements service conflict resolution
   - Handles service state management

3. **Resource Records**
   - A Records (IPv4 addresses)
   - PTR Records (service type enumeration)
   - SRV Records (service location)
   - TXT Records (service metadata)
   - Implements proper TTL management
   - Handles record conflicts
   - Implements DNS record caching

### Memory Management

- Static memory allocation where possible
- Limited dynamic allocation for service records
- Fixed-size buffers for DNS messages
- Efficient string handling for DNS names
- Proper cleanup of resources
- Memory pool for service records
- Cache management for DNS records

### Error Handling

- Robust error recovery
- Graceful degradation under memory pressure
- Clear error reporting to applications
- Proper error codes and messages
- Debug logging support
- Service conflict handling
- Network state management

## Library Interface

### Service Registration

```c
LONG BonamiRegisterService(struct BonamiService *service);
```
Registers a service for advertisement on the local network. The service structure contains:
- name: Service instance name
- type: Service type (e.g., "_http._tcp.local")
- port: Service port number
- txt: TXT record data

### Service Discovery

```c
LONG BonamiStartDiscovery(struct BonamiDiscovery *discovery);
```
Starts discovering services of a specific type. The discovery structure contains:
- type: Service type to discover
- callback: Function to call when services are found
- userData: User data passed to callback

### Service Resolution

```c
LONG BonamiResolveService(const char *name, const char *type, struct BonamiService *service);
```
Resolves a specific service instance to get its details.

### Service Type Enumeration

```c
LONG BonamiEnumerateServiceTypes(struct BonamiServiceType *types, LONG maxTypes);
```
Lists all service types currently available on the network.

### DNS Queries

```c
LONG BonamiQueryDNS(const char *name, WORD type, WORD class, struct DNSRecord *records, LONG maxRecords);
```
Performs arbitrary DNS queries.

## Installation

1. **System Requirements**
   - AmigaOS 3.x or higher
   - Roadshow TCP/IP stack
   - 1MB of free memory
   - 100KB of disk space

2. **Installation Steps**
   ```bash
   # Copy the daemon
   copy SYS:Utilities/BonAmi/bonami TO SYS:Utilities/BonAmi/
   
   # Copy the library
   copy SYS:Libs/bonami.library TO SYS:Libs/
   
   # Copy the tools
   copy SYS:Utilities/BonAmi/bonami-* TO SYS:Utilities/BonAmi/
   
   # Add to Startup-Sequence
   copy S/BonAmi-Startup TO S:Startup-Sequence
   ```

3. **Configuration**
   - Edit S:BonAmi-Startup to customize startup options
   - Set environment variables for debugging if needed
   - Configure log level in ENV:Bonami/config

## Building

Requirements:
- SAS/C or GCC for AmigaOS
- Roadshow TCP/IP stack
- AmigaOS 3.x or higher

Build steps:
```bash
# Using SAS/C
smake

# Using GCC
make
```

## Debugging

BonAmi supports several debugging options:
- Set log level in ENV:Bonami/config (0-2)
- Use bonami-register -v for verbose output
- Check SYS:Logs/BonAmi.log for daemon logs
- Monitor network interface status
- Check service conflict resolution

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Acknowledgments

- Inspired by Apple's Bonjour
- Built on Roadshow TCP/IP stack
- Thanks to the AmigaOS community 