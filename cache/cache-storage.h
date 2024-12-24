#ifndef CACHE_PROXY_CACHE_STORAGE
#define CACHE_PROXY_CACHE_STORAGE

#include <pthread.h>

#include "cache-entry.h"

#define MAP_SIZE            256

typedef struct _node {
    char *request;
    cacheEntry_t *response;
    struct _node *next;
} node_t;

struct {
    node_t **map;
    pthread_mutex_t mutex;
} typedef cacheStorage_t;

cacheStorage_t *cacheStorageCreate();
void cacheStorageDestroy(cacheStorage_t *storage);
int cacheStoragePut(cacheStorage_t *storage, char *req, cacheEntry_t *resp);
cacheEntry_t *cacheStorageGet(cacheStorage_t *storage, char *req);
int cacheStorageRemove(cacheStorage_t *storage, char *req);

#endif