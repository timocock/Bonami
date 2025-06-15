# Amiga Library-Daemon Pattern

This document describes a common pattern for implementing client-server architectures on AmigaOS, using a shared library as the client API and a long-running daemon process as the server.

## Architecture Overview

```
[Client Application] → [Shared Library] → [Daemon Process] → [System Resources]
```

## Key Components

### 1. Shared Library (Client API)
- Thin, stateless wrapper
- Handles message passing to daemon
- Provides a clean, synchronous API
- Manages connection to daemon
- Example:
```c
// Library provides simple API
LONG result = BARegisterService(&service);
```

### 2. Daemon Process (Server)
- Long-running background process
- Manages all state and resources
- Handles actual implementation
- Provides message-based interface
- Example:
```
Bonami [LOG/S] [LOGFILE/F] [DEBUG/S]
```

## Best Practices

### Process Management
- Daemon should be started manually or via startup-sequence
- No dependency on system service management
- Should handle its own process management
- Should provide status monitoring

### Communication
- Use Amiga message ports for IPC
- Implement request-reply pattern
- Handle connection loss gracefully
- Provide reconnection mechanism

### Resource Management
- Daemon owns all long-lived resources
- Library handles only ephemeral objects
- Use memory pools for efficiency
- Implement proper cleanup

### Error Handling
- Clear error codes
- Proper error propagation
- Graceful degradation
- Logging capabilities

## Implementation Pattern

### Library API (client)
```c
struct ServiceAPI {
    // Connection management
    LONG (*Connect)(void);
    LONG (*Disconnect)(void);
    
    // Core functionality
    LONG (*Execute)(struct Request *req, struct Reply *reply);
    
    // Status
    LONG (*GetStatus)(void);
};
```

### Daemon (server)
```c
struct ServiceDaemon {
    // Process management
    struct Process *process;
    struct MsgPort *msgPort;
    
    // Resource management
    struct MemoryPool *pool;
    
    // State management
    struct ServiceState *state;
    
    // Message handling
    void (*HandleMessage)(struct Message *msg);
};
```

## Startup Sequence

```c
// 1. Check if daemon is running
if (!IsDaemonRunning()) {
    // 2. Start daemon if needed
    StartDaemon();
    // 3. Wait for daemon to initialize
    WaitForDaemon();
}

// 4. Connect library to daemon
ConnectToDaemon();
```

## Message Protocol

```c
// Message structure
struct ServiceMessage {
    struct Message msg;
    ULONG type;
    APTR data;
    ULONG size;
};

// Message types
enum {
    MSG_CONNECT,
    MSG_DISCONNECT,
    MSG_REQUEST,
    MSG_REPLY,
    MSG_ERROR
};
```

## Error Recovery

```c
// Library side
LONG RetryWithBackoff(LONG (*func)(void)) {
    LONG result;
    ULONG retries = 0;
    
    while (retries < MAX_RETRIES) {
        result = func();
        if (result == SUCCESS) return result;
        
        // Exponential backoff
        Delay(1 << retries);
        retries++;
    }
    return result;
}
```

## Resource Management

```c
// Daemon side
struct ResourcePool {
    struct MemoryPool *pool;
    struct List resources;
    struct SignalSemaphore lock;
};

// Library side
struct TemporaryBuffer {
    APTR data;
    ULONG size;
};
```

## Monitoring

```c
// Status reporting
struct ServiceStatus {
    ULONG version;
    ULONG state;
    ULONG resources;
    ULONG errors;
};
```

## Advantages

1. **Reliability**
   - Clear separation of concerns
   - Robust error handling
   - Resource isolation

2. **Performance**
   - Efficient message passing
   - Resource pooling
   - Minimal overhead

3. **Maintainability**
   - Clean API design
   - Clear error reporting
   - Good debugging support

4. **Flexibility**
   - Easy to extend
   - Platform-specific optimizations
   - Configurable behavior

## Key Success Factors

1. Keeping the library thin and stateless
2. Managing all state in the daemon
3. Using efficient message passing
4. Implementing proper resource management
5. Providing clear error handling
6. Supporting monitoring and debugging

## Use Cases

This pattern is suitable for various Amiga services:
- Network services
- Device management
- File system services
- System monitoring
- Resource management 