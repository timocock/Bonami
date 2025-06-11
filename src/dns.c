#include <exec/types.h>
#include <exec/memory.h>
#include <proto/exec.h>
#include <string.h>
#include <stdio.h>

#include "../include/dns.h"
#include "../include/bonami.h"

/* Parse a DNS message */
LONG dnsParseMessage(const UBYTE *data, LONG len, struct DNSMessage *msg)
{
    // Basic validation
    if (!data || !msg || len < sizeof(struct DNSHeader))
        return BA_BADPARAM;
        
    // Validate message length
    if (len > MAX_PACKET_SIZE)
        return BA_BADPARAM;
        
    // Validate header fields
    struct DNSHeader *header = (struct DNSHeader *)data;
    if (ntohs(header->qdcount) > MAX_QUESTIONS ||
        ntohs(header->ancount) > MAX_ANSWERS ||
        ntohs(header->nscount) > MAX_AUTHORITY ||
        ntohs(header->arcount) > MAX_ADDITIONAL)
        return BA_BADPARAM;
        
    // Validate flags
    if ((header->flags1 & 0x3F) != 0) // Reserved bits must be 0
        return BA_BADPARAM;
        
    // Validate response code
    if ((header->flags2 & 0x0F) > 5) // Valid RCODE values are 0-5
        return BA_BADPARAM;

    /* Copy header */
    memcpy(&msg->header, data, sizeof(struct DNSHeader));
    msg->header.id = ntohs(msg->header.id);
    msg->header.qdcount = ntohs(msg->header.qdcount);
    msg->header.ancount = ntohs(msg->header.ancount);
    msg->header.nscount = ntohs(msg->header.nscount);
    msg->header.arcount = ntohs(msg->header.arcount);

    /* Set pointers to sections */
    UBYTE *ptr = (UBYTE *)data + sizeof(struct DNSHeader);
    
    /* Questions section */
    msg->questions = ptr;
    for (UWORD i = 0; i < msg->header.qdcount; i++) {
        ptr = dnsSkipName(ptr, len - (ptr - data));
        if (!ptr) return BA_BADPARAM;
        if (len - (ptr - data) < 4) return BA_BADPARAM; // Check for type and class
        ptr += 4; /* Skip type and class */
    }

    /* Answers section */
    msg->answers = ptr;
    for (UWORD i = 0; i < msg->header.ancount; i++) {
        ptr = dnsSkipName(ptr, len - (ptr - data));
        if (!ptr) return BA_BADPARAM;
        if (len - (ptr - data) < 10) return BA_BADPARAM; // Check for type, class, TTL, RDATA length
        UWORD rdlength = ntohs(*(UWORD *)(ptr + 8));
        if (len - (ptr - data) < 10 + rdlength) return BA_BADPARAM; // Check for RDATA
        ptr += 10 + rdlength;
    }

    /* Authority section */
    msg->authority = ptr;
    for (UWORD i = 0; i < msg->header.nscount; i++) {
        ptr = dnsSkipName(ptr, len - (ptr - data));
        if (!ptr) return BA_BADPARAM;
        if (len - (ptr - data) < 10) return BA_BADPARAM; // Check for type, class, TTL, RDATA length
        UWORD rdlength = ntohs(*(UWORD *)(ptr + 8));
        if (len - (ptr - data) < 10 + rdlength) return BA_BADPARAM; // Check for RDATA
        ptr += 10 + rdlength;
    }

    /* Additional section */
    msg->additional = ptr;
    for (UWORD i = 0; i < msg->header.arcount; i++) {
        ptr = dnsSkipName(ptr, len - (ptr - data));
        if (!ptr) return BA_BADPARAM;
        if (len - (ptr - data) < 10) return BA_BADPARAM; // Check for type, class, TTL, RDATA length
        UWORD rdlength = ntohs(*(UWORD *)(ptr + 8));
        if (len - (ptr - data) < 10 + rdlength) return BA_BADPARAM; // Check for RDATA
        ptr += 10 + rdlength;
    }

    return BA_OK;
}

/* Parse a DNS question */
LONG dnsParseQuestion(const UBYTE *data, LONG len, struct DNSQuestion *q)
{
    if (!data || !q)
        return BA_BADPARAM;

    /* Parse name */
    LONG nameLen = dnsLabelsToName(data, len, q->qname, BA_MAX_NAME_LEN);
    if (nameLen < 0)
        return BA_BADPARAM;

    /* Parse type and class */
    UBYTE *ptr = data + nameLen;
    if (len - nameLen < 4)
        return BA_BADPARAM;

    q->qtype = ntohs(*(UWORD *)ptr);
    q->qclass = ntohs(*(UWORD *)(ptr + 2));

    /* Validate type and class */
    if (q->qtype != DNS_TYPE_A && 
        q->qtype != DNS_TYPE_PTR && 
        q->qtype != DNS_TYPE_TXT && 
        q->qtype != DNS_TYPE_SRV && 
        q->qtype != DNS_TYPE_ANY)
        return BA_BADPARAM;

    if (q->qclass != DNS_CLASS_IN && q->qclass != DNS_CLASS_ANY)
        return BA_BADPARAM;

    return nameLen + 4;
}

/* Parse a DNS record */
LONG dnsParseRecord(const UBYTE *data, LONG len, struct DNSRecord *r)
{
    if (!data || !r)
        return BA_BADPARAM;

    /* Parse name */
    LONG nameLen = dnsLabelsToName(data, len, r->name, BA_MAX_NAME_LEN);
    if (nameLen < 0)
        return BA_BADPARAM;

    /* Parse type, class, TTL, and RDATA length */
    UBYTE *ptr = data + nameLen;
    if (len - nameLen < 10)
        return BA_BADPARAM;

    r->type = ntohs(*(UWORD *)ptr);
    r->class = ntohs(*(UWORD *)(ptr + 2));
    r->ttl = ntohl(*(ULONG *)(ptr + 4));
    r->rdlength = ntohs(*(UWORD *)(ptr + 8));

    /* Validate type and class */
    if (r->type != DNS_TYPE_A && 
        r->type != DNS_TYPE_PTR && 
        r->type != DNS_TYPE_TXT && 
        r->type != DNS_TYPE_SRV)
        return BA_BADPARAM;

    if (r->class != DNS_CLASS_IN)
        return BA_BADPARAM;

    /* Validate TTL */
    if (r->ttl > 0x7FFFFFFF) // Max 32-bit signed integer
        return BA_BADPARAM;

    /* Parse RDATA */
    if (len - nameLen - 10 < r->rdlength)
        return BA_BADPARAM;

    r->rdata = ptr + 10;

    /* Validate RDATA based on type */
    switch (r->type) {
        case DNS_TYPE_A:
            if (r->rdlength != 4)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_PTR:
            if (r->rdlength > 255)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_SRV:
            if (r->rdlength < 6)
                return BA_BADPARAM;
            break;
            
        case DNS_TYPE_TXT:
            if (r->rdlength > 255)
                return BA_BADPARAM;
            break;
    }

    return nameLen + 10 + r->rdlength;
}

/* Convert a domain name to DNS labels */
LONG dnsNameToLabels(const char *name, UBYTE *buffer, LONG buflen)
{
    if (!name || !buffer || buflen <= 0)
        return -1;

    LONG pos = 0;
    const char *start = name;

    while (*name) {
        if (*name == '.') {
            if (pos + (name - start) + 1 > buflen)
                return -1;
            buffer[pos++] = name - start;
            memcpy(buffer + pos, start, name - start);
            pos += name - start;
            start = name + 1;
        }
        name++;
    }

    if (pos + (name - start) + 2 > buflen)
        return -1;

    buffer[pos++] = name - start;
    memcpy(buffer + pos, start, name - start);
    pos += name - start;
    buffer[pos++] = 0;

    return pos;
}

/* Convert DNS labels to a domain name */
LONG dnsLabelsToName(const UBYTE *labels, LONG len, char *name, LONG namelen)
{
    if (!labels || !name || len <= 0 || namelen <= 0)
        return -1;

    LONG pos = 0;
    LONG labelLen;

    while ((labelLen = *labels) != 0) {
        if (labelLen & 0xC0) {
            /* Handle compression */
            UWORD offset = ((labelLen & 0x3F) << 8) | labels[1];
            if (offset >= len)
                return -1;
            labels = labels + offset;
            continue;
        }

        if (pos + labelLen + 1 > namelen)
            return -1;

        memcpy(name + pos, labels + 1, labelLen);
        pos += labelLen;
        name[pos++] = '.';
        labels += labelLen + 1;
    }

    if (pos > 0)
        name[pos - 1] = 0;
    else
        name[0] = 0;

    return labels - labels + 1;
}

/* Skip a DNS name in a message */
UBYTE *dnsSkipName(const UBYTE *data, LONG len)
{
    if (!data || len <= 0)
        return NULL;

    LONG pos = 0;
    UBYTE labelLen;

    while ((labelLen = data[pos]) != 0) {
        if (labelLen & 0xC0) {
            /* Handle compression */
            if (pos + 1 >= len)
                return NULL;
            return data + pos + 2;
        }

        if (pos + labelLen + 1 >= len)
            return NULL;

        pos += labelLen + 1;
    }

    return data + pos + 1;
} 