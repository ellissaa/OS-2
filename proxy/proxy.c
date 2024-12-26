#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client-handler.h"
#include "log/logger.h"
#include "proxy.h"

#define PORT            80
#define BACKLOG         30

static int createServSocket() {
    int servSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (servSocket == -1) {
        loggerError("Failed to create server socket, error: %s", strerror(errno));
        return -1;
    }

    int true = 1;
    setsockopt(servSocket, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true));

    struct sockaddr_in sAddr;
    memset(&sAddr, 0, sizeof(sAddr));
    sAddr.sin_family = AF_INET;
    sAddr.sin_addr.s_addr = INADDR_ANY;
    sAddr.sin_port = htons(PORT);

    int err = bind(servSocket, (struct sockaddr*) &sAddr, sizeof(sAddr));
    if (err) {
        loggerError("Failed to bind server socket, error: %s", strerror(errno));
        close(servSocket);
        return -1;
    }

    return servSocket;
}

proxy_t *proxyCreate(cacheStorage_t *cache, threadPool_t *threadpool) {
    if (!cache) {
        loggerError("proxyCreate: invalid cache");
        return NULL;
    }

    proxy_t *proxy = malloc(sizeof(*proxy));
    if (!proxy) {
        loggerError("proxyCreate: allocation failed");
        return NULL;
    }

    proxy->servSocket = createServSocket(); // принимаем подключения от клиентов
    if (proxy->servSocket == -1) {
        free(proxy);
        return NULL;
    }

    proxy->cache = cache;
    proxy->threadpool = threadpool;

    return proxy;
}

void proxyDestroy(proxy_t *proxy) {
    if (!proxy) return;
    close(proxy->servSocket);
    proxy->running = 0;
    free(proxy);
}

int proxyStart(proxy_t *proxy) {
    int err = listen(proxy->servSocket, BACKLOG);
    if (err) return -1;

    loggerInfo("Proxy started");

    proxy->running = 1;
    while (proxy->running) {                                        // бесконечно обрабатываем запросы от клиентов
        int clientSocket = accept(proxy->servSocket, NULL, NULL);   // сокет, связанный с новым клиентом
        if (clientSocket < 0) {
            loggerError("Error accepting connection: %s", strerror(errno));
            continue;
        }

        loggerInfo("Accepted new connection");

        clientHandlerArgs_t *args = malloc(sizeof(*args));
        if (!args) {
            loggerError("Failed to allocate memory for client handler arguments");
            shutdown(clientSocket, SHUT_RDWR);
            close(clientSocket);
            continue;
        }

        args->sockToClient = clientSocket;
        args->cache = proxy->cache;
        threadPoolSubmit(proxy->threadpool, handleClient, args);
    }

    return 0;
}