#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "client-handler.h"
#include "log/logger.h"

static int strEq(const char *s1, const char *s2, size_t len);
static int setTimeout(int sock, unsigned int ms);
static void disconnect(int sock);
static int connectToServ(const char *hostName);

static phrHeader_t *findHeader(phrHeader_t headers[], size_t numHeaders, const char *name);
static size_t getContentLen(phrHeader_t headers[], size_t numHeaders);

static int sendData(int sock, const char *data, size_t len);
static int sendFromCache(int sock, cacheEntry_t *cache);

static ssize_t readAndParseRequest(int sock, char *buf, size_t maxLen, reqParse_t *parseData);
static ssize_t handleResponse(int sockToServ, int sockToClient, char *req, cacheStorage_t *cacheStorage, int *status);

void handleClient(void *args) { // полностью работаем с клиентом - получаем запрос, отправляем ответ
    int sockToClient = ((clientHandlerArgs_t*) args)->sockToClient;
    cacheStorage_t *cacheStorage = ((clientHandlerArgs_t*) args)->cache;
    free(args);

    int sockToServ;
    char request[MAX_REQ_SIZE + 1] = {0};
    cacheEntry_t *cacheEntry = NULL;
    ssize_t reqLen, respLen;
    reqParse_t reqParse; 
    int err;

    err = setTimeout(sockToClient, TIMEOUT); // таймаут на ожидание ответа от клиента
    if (err) {
        loggerError("Failed to set timeout for client, error: %s", strerror(errno));
        disconnect(sockToClient);
        return;
    }

    reqLen = readAndParseRequest(sockToClient, request, MAX_REQ_SIZE, &reqParse);
    if (reqLen < 0) {
        loggerError("Failed to read client request");
        disconnect(sockToClient);
        return;
    }
    char path[reqParse.pathLen + 1];
    memcpy(path, reqParse.path, reqParse.pathLen);
    path[reqParse.pathLen] = 0;

    if (!strEq(reqParse.method, "GET", 3)) {
        loggerError("Unsupported method");
        disconnect(sockToClient);
        return;
    }

    /* Поиск записи в кэше и отправка */
    cacheEntry = cacheStorageGet(cacheStorage, path);
    if (cacheEntry) {
        loggerDebug("Found cache entry for resource %s", path);

        err = sendFromCache(sockToClient, cacheEntry);
        cacheEntryDereference(cacheEntry);
        disconnect(sockToClient);

        if (err) {
            loggerError("Failed to send response to client");
        }
        return;
    }

    /* Запись не найдена, обращаемся к серверу */
    loggerDebug("Cache entry for resource %s not found", path);

    /* Определяем доменное имя сервера */
    phrHeader_t *hostHeader = findHeader(reqParse.headers, reqParse.numHeaders, "Host");
    if (!hostHeader) {
        loggerError("Failed to fetch host name");
        disconnect(sockToClient);
        return;
    }
    char hostName[hostHeader->value_len + 1];
    memcpy(hostName, hostHeader->value, hostHeader->value_len);
    hostName[hostHeader->value_len] = 0;

    sockToServ = connectToServ(hostName);
    if (sockToServ < 0) {
        loggerError("Failed to connect to %s", hostName);
        disconnect(sockToClient);
        return;
    }
    loggerInfo("Connected to server %s", hostName);

    err = sendData(sockToServ, request, reqLen);
    if (err) {
        loggerError("Failed to send request to server, error: %s", strerror(errno));
        disconnect(sockToClient);
        disconnect(sockToServ);
        return;
    }
    loggerDebug("Sent request of %ld bytes to server %s", reqLen, hostName);

    int status;
    respLen = handleResponse(sockToServ, sockToClient, path, cacheStorage, &status);
    if (respLen < 0) {
        loggerError("Error handling response");
        disconnect(sockToClient);
        disconnect(sockToServ);
        return;
    }
    loggerInfo("Server %s responded with %ld bytes, status: %d", hostName, respLen, status);

    disconnect(sockToClient);
    disconnect(sockToServ);
}



static int strEq(const char *s1, const char *s2, size_t len) {
    return strncmp(s1, s2, len) == 0;
}

static int setTimeout(int sock, unsigned int ms) {
    struct timeval timeout;
    timeout.tv_sec = ms / 1000;
    timeout.tv_usec = ms % 1000 * 1000;

    int err1 = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    int err2 = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (err1 || err2) {
        return -1;
    }
    return 0;
}

static void disconnect(int sock) {
    shutdown(sock, SHUT_RDWR);
    close(sock);
}

static int connectToServ(const char *hostName) {
    struct addrinfo *addrInfo;
    int err;

    int sockToServ = socket(AF_INET, SOCK_STREAM, 0);
    if (!sockToServ) {
        loggerError("connectToServ: failed to create new socket");
        return -1;
    }

    err = setTimeout(sockToServ, TIMEOUT);
    if (err) {
        loggerError("connectToServ: failed to set timeout, error: %s", strerror(errno));
        close(sockToServ);
        return -1;
    }

    err = getaddrinfo(hostName, "http", NULL, &addrInfo);
    if (err) {
        loggerError("connectToServ: failed to resolve server address");
        close(sockToServ);
        return -1;
    }

    err = connect(sockToServ, addrInfo->ai_addr, addrInfo->ai_addrlen);
    if (err) {
        loggerError("connectToServ: failed to connect, error: %s", strerror(errno));
        close(sockToServ);
        freeaddrinfo(addrInfo);
        return -1;
    }

    freeaddrinfo(addrInfo);
    return sockToServ;
}



static phrHeader_t *findHeader(phrHeader_t headers[], size_t numHeaders, const char *name) {
    size_t len = strlen(name);
    for (size_t i = 0; i < numHeaders; i++) {
        if (headers[i].name_len == len && strEq(headers[i].name, name, len)) {
            return &headers[i];
        }
    }
    return NULL;
}

static size_t getContentLen(phrHeader_t headers[], size_t numHeaders) {
    phrHeader_t *contLenHeader = findHeader(headers, numHeaders, "Content-Length");
    if (!contLenHeader) return 0;

    char contentLength[contLenHeader->value_len + 1];
    memcpy(contentLength, contLenHeader->value, contLenHeader->value_len);
    contentLength[contLenHeader->value_len] = 0;

    long long contLen = atoll(contentLength);
    if (contLen < 0) return 0;
    return contLen;
}



static int sendData(int sock, const char *data, size_t len) {
    ssize_t sentTotal = 0;
    ssize_t sent;

    while (sentTotal != len) {
        sent = write(sock, data + sentTotal, len - sentTotal);
        if (sent == -1) return -1;
        sentTotal += sent;
    }
    return 0;
}

static int sendFromCache(int sock, cacheEntry_t *cache) {
    size_t sentTotal = 0;
    size_t lenToSend;
    int err, ret;

    pthread_mutex_lock(&cache->mutex); // чтобы не было race condition за запись в кэше, 1 читает, 1 пишет

    while (1) {
        while (cache->size == sentTotal && !cache->completed && !cache->canceled) { // делаем wait до момента, пока не придут/не обновятся данные
            pthread_cond_wait(&cache->updated, &cache->mutex);
        }

        if (cache->canceled) {
            ret = -1;
            break;
        }

        lenToSend = cache->size - sentTotal;
        err = sendData(sock, cache->buf + sentTotal, lenToSend);
        if (err) {
            ret = -1;
            break;
        }
        sentTotal = cache->size;

        if (cache->completed) {
            ret = 0;
            break;
        }
    }

    pthread_mutex_unlock(&cache->mutex);
    return ret;
}



static ssize_t readAndParseRequest(int sock, char *buf, size_t maxLen, reqParse_t *parseData) {
    int pret;
    ssize_t rret;
    size_t buflen = 0, prevbuflen = 0;

    while (1) {
        /* read the request */
        while ((rret = read(sock, buf + buflen, maxLen - buflen)) == -1 && errno == EINTR);
        if (rret == -1) {
            loggerError("Receive error: %s", strerror(errno));
            return -1;
        }
        if (rret == 0) {
            loggerInfo("Peer socket shutdown");
            return -1;
        }

        prevbuflen = buflen;
        buflen += rret;

        /* parse the request */
        parseData->numHeaders = sizeof(parseData->headers) / sizeof(parseData->headers[0]);
        pret = phr_parse_request(
            buf, buflen, &parseData->method, &parseData->methodLen, &parseData->path, &parseData->pathLen,
            &parseData->minorVersion, parseData->headers, &parseData->numHeaders, prevbuflen
        );

        if (pret > 0) {
            break;
        }

        else if (pret == -1) {
            loggerError("Error parsing request");
            return -1;
        }

        /* request is incomplete, continue the loop */
        assert(pret == -2);
        if (buflen == maxLen) {
            loggerError("Request is too long");
            return -1;
        }
    }

    return buflen;
}

static ssize_t handleResponse(int sockToServ, int sockToClient, char *req, cacheStorage_t *cacheStorage, int *status) {
    char buf[READ_BUF_LEN + 1];
    respParse_t parse;
    cacheEntry_t *newCache = NULL;
    ssize_t recvd;
    size_t recvdTotal = 0, headerLen, contentLen;
    char *headerEnd;
    int err;

    /* Ищем конец секции заголовков */
    do {
        if (recvdTotal == READ_BUF_LEN) {
            loggerError("Receive error: headers section is too long");
            return -1;
        }

        recvd = read(sockToServ, buf + recvdTotal, READ_BUF_LEN - recvdTotal);
        if (recvd == -1) {
            loggerError("Receive error: %s", strerror(errno));
            return -1;
        }
        if (recvd == 0) {
            loggerError("Receive error: server disconnected");
            return -1;
        }

        recvdTotal += recvd;
        buf[recvdTotal] = 0;
    } while ((headerEnd = strstr(buf, "\r\n\r\n")) == NULL);
    headerEnd += strlen("\r\n\r\n");
    headerLen = headerEnd - buf;

    /* Парсим секцию заголовков */
    parse.numHeaders = sizeof(parse.headers) / sizeof(parse.headers[0]);
    err = phr_parse_response(
        buf, headerLen, &parse.minorVersion, &parse.status, &parse.msg,
        &parse.msgLen, parse.headers, &parse.numHeaders, 0
    );
    if (err < 0) {
        loggerError("Failed to parse response, error: %i", err);
        return -1;
    }
    *status = parse.status;

    contentLen = getContentLen(parse.headers, parse.numHeaders);

    /* Отправляем клиенту все данные, полученные на текущий момент */
    err = sendData(sockToClient, buf, recvdTotal);
    if (err) {
        loggerError("Failed to send data back to client");
        return -1;
    }

    /* Если ответ успешный, создаем для него кэш-запись */
    if (parse.status == 200) {
        newCache = cacheEntryCreate();
        if (!newCache) {
            loggerError("Failed to create new cache entry");
        }
    }

    /* Добавляем в запись все данные, полученные на текущий момент */
    err = cacheEntryAppend(newCache, buf, recvdTotal);
    if (err) {
        loggerError("Failed to append data to cache entry");
        cacheEntryDestroy(newCache);
        newCache = NULL;
    }

    /* Сразу добавляем запись в хранилище */
    err = cacheStoragePut(cacheStorage, req, newCache);
    if (err) {
        loggerError("Failed to add cache entry to storage");
        cacheEntryDestroy(newCache);
        newCache = NULL;
    }

    /* Получаем оставшиеся данные от сервера, пересылаем клиенту и сохраняем в кэш */
    ssize_t remaining = headerLen + contentLen - recvdTotal;
    while (remaining > 0) {
        recvd = read(sockToServ, buf, READ_BUF_LEN);
        if (recvd <= 0) {
            if (recvd == -1) loggerError("Receive error: %s", strerror(errno));
            if (recvd == 0) loggerError("Receive error: server disconnected");
            cacheEntrySetCanceled(newCache);
            cacheStorageRemove(cacheStorage, req);
            return -1;
        }

        remaining -= recvd;
        recvdTotal += recvd;

        err = sendData(sockToClient, buf, recvd);
        if (err) {
            loggerError("Failed to send data back to client");
            cacheEntrySetCanceled(newCache);
            cacheStorageRemove(cacheStorage, req);
            return -1;
        }

        err = cacheEntryAppend(newCache, buf, recvd);
        if (err) {
            loggerError("Failed to append data to cache entry");
            cacheEntrySetCanceled(newCache);
            cacheStorageRemove(cacheStorage, req);
            newCache = NULL;
        }
    }

    cacheEntrySetCompleted(newCache);
    loggerDebug("Cached response to %s", req);
    return recvdTotal;
}