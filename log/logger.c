#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "logger.h"

#define COLOR_RESET     "\033[0m"
#define COLOR_RED       "\033[31m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"

#define LOG_GENERAL(lvlText, color, format)                 \
    va_list args;                                           \
    va_start(args, format);                                 \
    loggerLog(lvlText, color, format, args);                \
    va_end(args)

static logger_t *logger;

static void loggerLog(char *lvlText, char *color, char *format, va_list args) {
    fprintf(stderr, "%s%s: ", color, lvlText);
    vfprintf(stderr, format, args);
    fprintf(stderr, COLOR_RESET "\n");
}

int loggerInit(logLevel_t logLevel) {
    logger = malloc(sizeof(*logger));
    if (!logger) {
        return -1;
    }
    logger->logLevel = logLevel;
    return 0;
}

void loggerFinalize() {
    free(logger);
}

void loggerCritical(char *format, ...) {
    if (logger->logLevel < LOG_CRITICAL) return;
    LOG_GENERAL("CRITICAL", COLOR_RED, format);
}

void loggerError(char *format, ...) {
    if (logger->logLevel < LOG_ERROR) return;
    LOG_GENERAL("ERROR", COLOR_MAGENTA, format);
}

void loggerInfo(char *format, ...) {
    if (logger->logLevel < LOG_INFO) return;
    LOG_GENERAL("INFO", COLOR_YELLOW, format);
}

void loggerDebug(char *format, ...) {
    if (logger->logLevel < LOG_DEBUG) return;
    LOG_GENERAL("DEBUG", COLOR_BLUE, format);
}