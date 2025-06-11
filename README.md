# BonAmi - mDNS Implementation for AmigaOS

BonAmi is an mDNS (multicast DNS) implementation for AmigaOS, designed to work with the Roadshow TCP/IP stack. It provides functionality similar to Apple's Bonjour, allowing Amiga computers to discover and advertise services on their local network.

## Architecture Overview

### Core Components

1. **mDNS Daemon (bonamid)**
   - Runs as a background process
   - Handles multicast DNS queries and responses
   - Manages service registration and discovery
   - Uses Roadshow's bsdsocket.library for network communication

2. **Library Interface (bonami.library)**
   - Provides API for applications to register and discover services
   - Handles communication with the daemon
   - Implements the mDNS protocol according to RFC 6762

3. **Command Line Tools**
   - `bonami-register`: Register services
   - `bonami-browse`: Browse available services
   - `bonami-query`: Query specific service types

### Technical Constraints

- IPv4 only (no IPv6 support)
- C89 compatible code
- Uses Roadshow's bsdsocket.library
- Limited to AmigaOS system calls and APIs
- Memory efficient design for classic Amiga hardware

### Protocol Implementation

1. **Multicast Communication**
   - Uses UDP port 5353
   - Multicast address: 224.0.0.251
   - TTL: 255 (local network only)

2. **Service Discovery**
   - Implements DNS-SD (DNS Service Discovery)
   - Supports service type enumeration
   - Handles service instance resolution

3. **Resource Records**
   - A Records (IPv4 addresses)
   - PTR Records (service type enumeration)
   - SRV Records (service location)
   - TXT Records (service metadata)

### Memory Management

- Static memory allocation where possible
- Limited dynamic allocation for service records
- Fixed-size buffers for DNS messages
- Efficient string handling for DNS names

### Error Handling

- Robust error recovery
- Graceful degradation under memory pressure
- Clear error reporting to applications

## Building

Requirements:
- SAS/C or GCC for AmigaOS
- Roadshow TCP/IP stack
- AmigaOS 3.x or higher

## License

This project is licensed under the MIT License - see the LICENSE file for details. 