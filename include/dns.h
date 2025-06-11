#ifndef DNS_H
#define DNS_H

#include <exec/types.h>

/* DNS Message Header */
struct DNSHeader {
    UWORD id;        /* Identification */
    UBYTE flags1;    /* First byte of flags */
    UBYTE flags2;    /* Second byte of flags */
    UWORD qdcount;   /* Number of questions */
    UWORD ancount;   /* Number of answers */
    UWORD nscount;   /* Number of authority records */
    UWORD arcount;   /* Number of additional records */
};

/* DNS Message Flags */
#define DNS_FLAG_QR    0x80    /* Query/Response flag */
#define DNS_FLAG_AA    0x04    /* Authoritative Answer */
#define DNS_FLAG_TC    0x02    /* Truncation */
#define DNS_FLAG_RD    0x01    /* Recursion Desired */
#define DNS_FLAG_RA    0x80    /* Recursion Available */
#define DNS_FLAG_Z     0x40    /* Reserved */
#define DNS_FLAG_AD    0x20    /* Authentic Data */
#define DNS_FLAG_CD    0x10    /* Checking Disabled */
#define DNS_FLAG_RCODE 0x0F    /* Response Code */

/* DNS Record Types */
#define DNS_TYPE_A      1    /* Host Address */
#define DNS_TYPE_PTR   12    /* Domain Name Pointer */
#define DNS_TYPE_TXT   16    /* Text Strings */
#define DNS_TYPE_SRV   33    /* Server Selection */
#define DNS_TYPE_ANY  255    /* Any Type */

/* DNS Class Values */
#define DNS_CLASS_IN    1    /* Internet */
#define DNS_CLASS_ANY 255    /* Any Class */

/* DNS Message Structure */
struct DNSMessage {
    struct DNSHeader header;
    UBYTE *questions;    /* Question section */
    UBYTE *answers;      /* Answer section */
    UBYTE *authority;    /* Authority section */
    UBYTE *additional;   /* Additional section */
};

/* DNS Question Structure */
struct DNSQuestion {
    char *qname;         /* Domain name */
    UWORD qtype;         /* Question type */
    UWORD qclass;        /* Question class */
};

/* DNS Resource Record Structure */
struct DNSRecord {
    char *name;          /* Domain name */
    UWORD type;          /* Record type */
    UWORD class;         /* Record class */
    ULONG ttl;           /* Time to live */
    UWORD rdlength;      /* Length of RDATA */
    UBYTE *rdata;        /* Record data */
};

/* Function prototypes */
LONG dnsParseMessage(const UBYTE *data, LONG len, struct DNSMessage *msg);
LONG dnsParseQuestion(const UBYTE *data, LONG len, struct DNSQuestion *q);
LONG dnsParseRecord(const UBYTE *data, LONG len, struct DNSRecord *r);
LONG dnsBuildMessage(UBYTE *buffer, LONG buflen, const struct DNSMessage *msg);
LONG dnsBuildQuestion(UBYTE *buffer, LONG buflen, const struct DNSQuestion *q);
LONG dnsBuildRecord(UBYTE *buffer, LONG buflen, const struct DNSRecord *r);
LONG dnsNameToLabels(const char *name, UBYTE *buffer, LONG buflen);
LONG dnsLabelsToName(const UBYTE *labels, LONG len, char *name, LONG namelen);
UBYTE *dnsSkipName(const UBYTE *data, LONG len);

#endif /* DNS_H */ 