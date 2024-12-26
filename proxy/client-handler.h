#ifndef CACHE_PROXY_CLIENT_HANDLER
#define CACHE_PROXY_CLIENT_HANDLER

#include "cache/cache-storage.h"
#include "http-parser/parser.h"

#define TIMEOUT             10000
#define MAX_REQ_SIZE        (1024 * 8)
#define MAX_NUM_HEADERS     20
#define READ_BUF_LEN        4096

typedef struct phr_header phrHeader_t;

typedef struct {
    const char *method;                     
    const char *path;                       // URL
    phrHeader_t headers[MAX_NUM_HEADERS];   // служебная информация
    size_t methodLen;
    size_t pathLen;
    size_t numHeaders;
    int minorVersion;
} reqParse_t;

typedef struct {
    int minorVersion;
    int status;
    const char *msg;
    size_t msgLen;
    phrHeader_t headers[MAX_NUM_HEADERS];
    size_t numHeaders;
} respParse_t;

typedef struct {
    int sockToClient;
    cacheStorage_t *cache;
} clientHandlerArgs_t;

void handleClient(void *args);

#endif