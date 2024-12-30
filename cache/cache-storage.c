#include <stdlib.h>
#include <string.h>

#include "cache-storage.h"
#include "log/logger.h"

static unsigned int hash(const char *str, size_t len) {
    unsigned int hash = 0;
    for (size_t i = 0; i < len; i++) {
        hash = hash * 31 + *str++;
    }
    return hash % MAP_SIZE;
}

static int strEq(char *s1, char *s2) {
    return strcmp(s1, s2) == 0;
}

cacheStorage_t *cacheStorageCreate() {
    cacheStorage_t *storage = malloc(sizeof(*storage));
    if (!storage) return NULL;

    storage->map = calloc(MAP_SIZE, sizeof(node_t*)); // массив указателей на ноды
    if (!storage->map) {
        free(storage);
        return NULL;
    }

    pthread_mutex_init(&storage->mutex, NULL);

    loggerDebug("cacheStorageCreate: created %p", storage);

    return storage;
}

void cacheStorageDestroy(cacheStorage_t *storage) {
    if (!storage) return;

    pthread_mutex_lock(&storage->mutex);

    for (int i = 0; i < MAP_SIZE; i++) {
        node_t* current = storage->map[i];
        while (current) {
            node_t* temp = current;
            current = current->next;

            /* удаляем ссылку и очищаем ресурсы ноды */
            cacheEntryDereference(temp->response);
            free(temp->request);
            free(temp);
        }
    }

    free(storage->map);
    pthread_mutex_unlock(&storage->mutex);
    pthread_mutex_destroy(&storage->mutex);
    free(storage);

    loggerDebug("cacheStorageDestroy: destroyed %p", storage);
}

int cacheStoragePut(cacheStorage_t *storage, char *req, cacheEntry_t *resp) {
    if (!storage || !req || !resp) return 0;

    size_t reqLen = strlen(req);
    unsigned long index = hash(req, reqLen); // переданную строку преобразовали в индекс, по которому в дальнейшем будем обращаться
    node_t *current = storage->map[index];

    /* Проверяем на наличие записи по данному запросу */
    while (current) {
        if (strEq(current->request, req)) {                 // запись с таким же ключом найдена
            if (current->response != resp) {                // записанный ответ != переданному ответу (объекты)
                cacheEntryDereference(current->response);   // удаляем ссылку на старый ответ
                current->response = resp;                   // заменяем на новый ответ
                cacheEntryReference(resp);                  // добавлена ссылка на новый ответ
                loggerDebug("cacheStoragePut: modified node, key '%s'", req);
            }

            return 0;
        }
        current = current->next;
    }

    /* Запись не найдена, создаем новую */
    node_t *newNode = malloc(sizeof(*newNode));
    char *request = malloc((reqLen + 1) * sizeof(*request));
    if (!newNode || !request) {
        free(newNode);
        free(request);
        return -1;
    }

    memcpy(request, req, reqLen);           // сохраняем содержимое запроса
    request[reqLen] = 0;                    // строка завершена
    newNode->request = request;

    newNode->response = resp;
    cacheEntryReference(resp);              // добавлена ссылка на новый ответ

    newNode->next = storage->map[index];    // добавлем в начало списка
    storage->map[index] = newNode;

    loggerDebug("cacheStoragePut: created new node, key '%s'", req);
    return 0;
}

/* возвращаем запись по данному запросу */
cacheEntry_t *cacheStorageGet(cacheStorage_t *storage, char *req) { 
    if (!storage || !req) return NULL;

    size_t reqLen = strlen(req);
    unsigned long index = hash(req, reqLen);
    node_t *current = storage->map[index];

    while (current) {
        if (strEq(current->request, req)) {             // запись найдена
            cacheEntryReference(current->response);     // добавили ссылку на эту запись
            loggerDebug("cacheStorageGet: found node, key '%s'", current->request);
            pthread_mutex_unlock(&storage->mutex);
            return current->response;
        }
        current = current->next; // для поиска нужной ноды по заданному хэшу
    }

    return NULL;
}

int cacheStorageRemove(cacheStorage_t *storage, char *req) {
    if (!storage || !req) return 0;

    pthread_mutex_lock(&storage->mutex);

    size_t reqLen = strlen(req);
    unsigned long index = hash(req, reqLen);
    node_t* current = storage->map[index];
    node_t* previous = NULL;

    while (current) {
        if (strEq(current->request, req)) {                 // запись найдена
            if (previous) {
                previous->next = current->next;
            } else {
                storage->map[index] = current->next;
            }

            loggerDebug("cacheStorageRemove: found node, key '%s'", current->request);

            cacheEntryDereference(current->response);       // ссылки из мапы больше нет, удаляем
            free(current->request);                         // очищаем память, занятую нодой, но не ответом
            free(current);
            pthread_mutex_unlock(&storage->mutex);
            return 0;
        }
        previous = current;
        current = current->next;
    }

    pthread_mutex_unlock(&storage->mutex);
    return -1;
}