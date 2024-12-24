#ifndef CACHE_PROXY_THREAD_POOL
#define CACHE_PROXY_THREAD_POOL

#include <stdatomic.h>
#include <pthread.h>

typedef struct {
    long id;
    void (*run) (void *);
    void *arg;
} task_t;

typedef struct {
    task_t *tasks; // таски для исполнения
    size_t capacity; // кол-во тасков макс
    size_t size; // кол-во тасков в очереди

    int first;
    int last;

    pthread_mutex_t mutex;
    pthread_cond_t gotTasks; // появились задания
    pthread_cond_t gotSlots; // появились свободные места

    pthread_t *threads;
    int numThreads;

    atomic_int stopped; // говорит, что тредпул больше не работает
} threadPool_t;

threadPool_t *threadPoolCreate(int numThreads, size_t queueCapacity);
void threadPoolSubmit(threadPool_t *pool, void (*run) (void *), void *arg);
void threadPoolStop(threadPool_t *pool);

#endif 