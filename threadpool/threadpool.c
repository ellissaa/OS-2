#include <stdlib.h>

#include "log/logger.h"
#include "threadpool.h"

static long idCnt; // айди для тасков

static void *workerRoutine(void *arg);

threadPool_t *threadPoolCreate(int numThreads, size_t queueCapacity) {
    threadPool_t *pool = malloc(sizeof(*pool));
    if (pool == NULL) return NULL;

    pool->tasks = calloc(queueCapacity, sizeof(task_t));
    if (pool->tasks == NULL) {
        free(pool);
        return NULL;
    }

    pool->threads = calloc(numThreads, sizeof(pthread_t));
    if (pool->threads == NULL) {
        free(pool->tasks);
        free(pool);
        return NULL;
    }

    pool->capacity = queueCapacity;
    pool->size = 0;
    pool->first = 0;
    pool->last = 0;
    pool->numThreads = numThreads;
    pool->stopped = 0;

    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->gotTasks, NULL);
    pthread_cond_init(&pool->gotSlots, NULL);

    for (int i = 0; i < numThreads; i++) {
        pthread_create(&pool->threads[i], NULL, workerRoutine, pool);
    }

    return pool;
}

void threadPoolSubmit(threadPool_t *pool, void (*run) (void *), void *arg) {
    if (pool->stopped) {
        loggerError("Can't submit a new task: thread pool is stopped");
        return;
    }

    pthread_mutex_lock(&pool->mutex);

    while (pool->size == pool->capacity && !pool->stopped) { // пока нет свободных мест или пока не остановили
        pthread_cond_wait(&pool->gotSlots, &pool->mutex);
    }

    if (pool->stopped) {
        pthread_mutex_unlock(&pool->mutex);
        return;
    }

    // добавили таск
    pool->tasks[pool->last].id = idCnt++;
    pool->tasks[pool->last].run = run;
    pool->tasks[pool->last].arg = arg;
    pool->last = (pool->last + 1) % pool->capacity;
    pool->size++;

    pthread_cond_signal(&pool->gotTasks);
    pthread_mutex_unlock(&pool->mutex);
}

void threadPoolStop(threadPool_t *pool) {
    pool->stopped = 1;

    pthread_cond_broadcast(&pool->gotTasks);
    pthread_cond_broadcast(&pool->gotSlots);

    for (int i = 0; i < pool->numThreads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    free(pool->tasks);
    free(pool->threads);

    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->gotTasks);
    pthread_cond_destroy(&pool->gotSlots);

    free(pool);
}

static void *workerRoutine(void *arg) {
    threadPool_t *pool = (threadPool_t*) arg;
    while (1) {
        pthread_mutex_lock(&pool->mutex);

        while (pool->size == 0 && !pool->stopped) { // ждем новых тасков в очереди
            pthread_cond_wait(&pool->gotTasks, &pool->mutex);
        }

        if (pool->stopped) {
            pthread_mutex_unlock(&pool->mutex);
            pthread_exit(NULL);
        }

        // достаем таск из очереди
        task_t task = pool->tasks[pool->first];
        pool->first = (pool->first + 1) % pool->capacity;
        pool->size--;

        pthread_cond_signal(&pool->gotSlots);
        pthread_mutex_unlock(&pool->mutex);

        task.run(task.arg);
    }
}