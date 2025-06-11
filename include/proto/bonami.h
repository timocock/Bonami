/*
** bonami.h -- BonAmi mDNS Library header
**
** Copyright (C) 2024 AmigaZen
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Lesser General Public
** License as published by the Free Software Foundation; either
** version 2.1 of the License, or (at your option) any later version.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Lesser General Public License for more details.
**
** You should have received a copy of the GNU Lesser General Public
** License along with this library; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef PROTO_BONAMI_H
#define PROTO_BONAMI_H

#include <exec/types.h>
#include <exec/libraries.h>
#include <exec/interfaces.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Library version */
#define BONAMI_VERSION 40

/* Error codes */
#define BA_OK          0
#define BA_NOMEM       1
#define BA_INVALID     2
#define BA_DUPLICATE   3
#define BA_NOTFOUND    4
#define BA_TIMEOUT     5
#define BA_NETWORK     6
#define BA_VERSION     7

/* Service structure */
struct BAService {
    STRPTR name;        /* Service name */
    STRPTR type;        /* Service type (e.g., "_http._tcp") */
    STRPTR host;        /* Host name */
    UWORD  port;        /* Port number */
    STRPTR txt;         /* TXT record data */
};

/* Discovery structure */
struct BADiscovery {
    STRPTR type;        /* Service type to discover */
    VOID   (*callback)(struct BAService *service, APTR userData); /* Callback function */
    APTR   userData;    /* User data passed to callback */
};

/* Interface structure */
struct BAInterface {
    STRPTR name;        /* Interface name */
    ULONG  address;     /* IP address */
    ULONG  netmask;     /* Network mask */
    BOOL   active;      /* Interface status */
};

/* Library base structure */
struct BonAmiBase {
    struct Library lib;
    UWORD pad;
    APTR  sysBase;
    APTR  dosBase;
    APTR  roadshowBase;
    APTR  socketBase;
    APTR  msgPort;
    APTR  replyPort;
};

/* Function prototypes */
LONG BARegisterService(struct BAService *service);
LONG BAUnregisterService(STRPTR name, STRPTR type);
LONG BADiscoverServices(STRPTR type, struct BAService **services, ULONG *numServices);
LONG BAStartDiscovery(struct BADiscovery *discovery);
LONG BAStopDiscovery(struct BADiscovery *discovery);
LONG BAResolveService(STRPTR name, STRPTR type, struct BAService *service);
LONG BAMonitorServices(STRPTR type, VOID (*callback)(struct BAService *service, APTR userData), APTR userData);
LONG BAUpdateService(STRPTR name, STRPTR type, STRPTR txt);
STRPTR BACreateTXTRecord(STRPTR key, STRPTR value);
VOID BAFreeTXTRecord(STRPTR record);

/* AmigaOS 4 interface */
#ifdef __amigaos4__
struct BonAmiIFace {
    struct InterfaceData Data;
    
    /* Library functions */
    LONG (*BARegisterService)(struct BonAmiIFace *Self, struct BAService *service);
    LONG (*BAUnregisterService)(struct BonAmiIFace *Self, STRPTR name, STRPTR type);
    LONG (*BADiscoverServices)(struct BonAmiIFace *Self, STRPTR type, struct BAService **services, ULONG *numServices);
    LONG (*BAStartDiscovery)(struct BonAmiIFace *Self, struct BADiscovery *discovery);
    LONG (*BAStopDiscovery)(struct BonAmiIFace *Self, struct BADiscovery *discovery);
    LONG (*BAResolveService)(struct BonAmiIFace *Self, STRPTR name, STRPTR type, struct BAService *service);
    LONG (*BAMonitorServices)(struct BonAmiIFace *Self, STRPTR type, VOID (*callback)(struct BAService *service, APTR userData), APTR userData);
    LONG (*BAUpdateService)(struct BonAmiIFace *Self, STRPTR name, STRPTR type, STRPTR txt);
    STRPTR (*BACreateTXTRecord)(struct BonAmiIFace *Self, STRPTR key, STRPTR value);
    VOID (*BAFreeTXTRecord)(struct BonAmiIFace *Self, STRPTR record);
};
#endif

#ifdef __cplusplus
}
#endif

#endif /* PROTO_BONAMI_H */ 