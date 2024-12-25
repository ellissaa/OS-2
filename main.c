#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cache/cache-storage.h"
#include "log/logger.h"
#include "proxy/proxy.h"
#include "threadpool/threadpool.h"

#define NUM_WORKERS             16
#define TASK_QUEUE_CAP          100

proxy_t *proxy;

void stop(int sig) {
    if (!proxy) return;
    proxy->running = 0;
    loggerInfo("Stopped proxy");
}

int main(int argc, char **argv) {
    int err;
    loggerInit(LOG_DEBUG);

    struct sigaction act;
    act.sa_handler = stop;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    err = sigaction(SIGINT, &act, NULL);
    if (err) {
        loggerCritical("Failed to setup SIGINT handler, error: %s", strerror(errno));
        abort();
    }

    cacheStorage_t *cache = cacheStorageCreate();
    if (!cache) {
        loggerCritical("Failed to create cache storage");
        abort();
    }

    threadPool_t *threadpool = threadPoolCreate(NUM_WORKERS, TASK_QUEUE_CAP);
    if (!threadpool) {
        loggerCritical("Failed to create threadpool");
        abort();
    }

    proxy = proxyCreate(cache, threadpool);
    if (!proxy) {
        loggerCritical("Error creating proxy");
        abort();
    }

    err = proxyStart(proxy);
    if (err) {
        loggerCritical("Error starting proxy");
        abort();
    }

    proxyDestroy(proxy);
    threadPoolStop(threadpool);
    cacheStorageDestroy(cache);

    loggerFinalize();
    return 0;
}