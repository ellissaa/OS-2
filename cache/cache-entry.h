#ifndef CACHE_PROXY_CACHE_ENTRY
#define CACHE_PROXY_CACHE_ENTRY

#define _GNU_SOURCE

#include <pthread.h>
#include <stdatomic.h>

struct {
    char *buf;
    size_t size; // сколько байт в буфере
    size_t capacity; // размер буфера

    int completed; // запись полностью прочитана
    int canceled; // какая-то ошибка произошла и больше отправлять ничего не нужно

    pthread_mutex_t mutex;
    pthread_cond_t updated; // УП для того, чтобы разбудить поток в случае обновлений

    int refCount; // счетчик ссылок для очистки памяти, которая была занята данной записью
    pthread_spinlock_t refCountLock; 

    /* зачем это сделано? если работающий поток хочет удалить запись из хранилища (со всеми записями кэша - мапы), 
    то по красоте нужно освобождать память; для целостности структуры данных и избегания ошибок (вроде двойного free)
    есть счетчик ссылок, который показывает количество работающих потоков с записью. */
    
} typedef cacheEntry_t;

cacheEntry_t *cacheEntryCreate();
void cacheEntryDestroy(cacheEntry_t *entry);
int cacheEntryAppend(cacheEntry_t *entry, char *newData, size_t size);

void cacheEntrySetCompleted(cacheEntry_t *entry);
void cacheEntrySetCanceled(cacheEntry_t *entry);

void cacheEntryReference(cacheEntry_t *entry); // увеличение кол-ва ссылок
void cacheEntryDereference(cacheEntry_t *entry); // уменьшение -//-

#endif