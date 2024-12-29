#include <stdlib.h>
#include <string.h>

#include "cache-entry.h"
#include "log/logger.h"

#define CHUNK_SIZE          (1024 * 8)

cacheEntry_t *cacheEntryCreate() { // создание записи в кэше
    cacheEntry_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return NULL;
    entry->refCount = 1;
    pthread_mutex_init(&entry->mutex, NULL);
    pthread_cond_init(&entry->updated, NULL);
    pthread_spin_init(&entry->refCountLock, 0);

    loggerDebug("cacheEntryCreate: created %p", entry);

    return entry;
}

void cacheEntryDestroy(cacheEntry_t *entry) {
    if (!entry) return;
    free(entry->buf);
    entry->buf = NULL;

    pthread_mutex_destroy(&entry->mutex);
    pthread_cond_destroy(&entry->updated);
    pthread_spin_destroy(&entry->refCountLock);
    free(entry);

    loggerDebug("cacheEntryDestroy: destroyed %p", entry);
}

int cacheEntryAppend(cacheEntry_t *entry, char *newData, size_t size) { // добавление данных
    if (!entry || !newData) return 0;

    pthread_mutex_lock(&entry->mutex);

    size_t newSize = entry->size + size;
    if (entry->capacity < newSize) {
        size_t newCapacity = newSize + CHUNK_SIZE;
        char *newBuf = realloc(entry->buf, newCapacity);
        if (newBuf == NULL) {
            pthread_mutex_unlock(&entry->mutex);
            return -1;
        }
        entry->buf = newBuf;
        entry->capacity = newCapacity;
    }

    memcpy(entry->buf + entry->size, newData, size);
    entry->size += size;

    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);

    return 0;
}

void cacheEntrySetCompleted(cacheEntry_t *entry) { 
    if (!entry) return;
    pthread_mutex_lock(&entry->mutex);
    entry->completed = 1;
    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);
}

void cacheEntrySetCanceled(cacheEntry_t *entry) {
    if (!entry) return;
    pthread_mutex_lock(&entry->mutex);
    entry->canceled = 1;
    pthread_cond_broadcast(&entry->updated);
    pthread_mutex_unlock(&entry->mutex);
}

void cacheEntryReference(cacheEntry_t *entry) {
    if (!entry) return;
    pthread_spin_lock(&entry->refCountLock);
    entry->refCount++;
    pthread_spin_unlock(&entry->refCountLock);
}

void cacheEntryDereference(cacheEntry_t *entry) {
    if (!entry) return;
    pthread_spin_lock(&entry->refCountLock);
    entry->refCount--;

    if (entry->refCount == 0) {
        pthread_spin_unlock(&entry->refCountLock);
        cacheEntryDestroy(entry);
        return;
    }
    
    pthread_spin_unlock(&entry->refCountLock);
}