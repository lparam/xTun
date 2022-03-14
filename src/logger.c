#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#ifdef ANDROID
#include <android/log.h>
#endif

#include "uv.h"
#include "logger.h"


#define LOG_MESSAGE_SIZE 256

static int _clean = 0;
static int _syslog = 0;
static int _level = LOG_INFO;

#ifdef _MSC_VER
#define vsnprintf _vsnprintf
#endif

static const char *levels[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"
};

#ifndef ANDROID
static const char *colors[] = {
    "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;31m", "\033[01;33m", "\033[01;33m", "\033[01;32m", "\033[01;36m"
};
#endif

static void
log2std(FILE *file, const char *msg) {
    fprintf(file, "%s", msg);
}

void
logger_log(uint32_t level, const char *msg, ...) {
    char tmp[LOG_MESSAGE_SIZE];
    char m[LOG_MESSAGE_SIZE + 64] = { 0 };

    if (level > _level) {
        return;
    }

    va_list ap;
    va_start(ap, msg);
    vsnprintf(tmp, LOG_MESSAGE_SIZE, msg, ap);
    va_end(ap);

    if (_syslog) {
        syslog(level, "<%s> %s\n", levels[level], tmp);

    } else if (_clean) {
        sprintf(m, "<%s> %s\n", levels[level], tmp);
        log2std(stdout, m);

    } else {
#ifdef ANDROID
        if (level <= LOG_ERR) {
            level = ANDROID_LOG_ERROR;
        } else if (level == LOG_WARNING) {
            level = ANDROID_LOG_WARN;
        } else if (level == LOG_DEBUG) {
            level = ANDROID_LOG_DEBUG;
        } else {
            level = ANDROID_LOG_INFO;
        }
        __android_log_print(level, "xTun", "%s", tmp);
#else
        time_t curtime = time(NULL);
        struct tm *loctime = localtime(&curtime);
        char timestr[20];
        strftime(timestr, 20, "%Y/%m/%d %H:%M:%S", loctime);
        sprintf(m, "%s%s <%s>\033[0m %s\n", colors[level], timestr, levels[level], tmp);
        log2std(stdout, m);
#endif
    }
}

void
logger_stderr(const char *msg, ...) {
    char timestr[20];
    time_t curtime = time(NULL);
    struct tm *loctime = localtime(&curtime);

    char tmp[LOG_MESSAGE_SIZE];

    va_list ap;
    va_start(ap, msg);
    vsnprintf(tmp, LOG_MESSAGE_SIZE, msg, ap);
    va_end(ap);

    strftime(timestr, 20, "%Y/%m/%d %H:%M:%S", loctime);
    char m[300] = { 0 };
    sprintf(m, "\033[01;31m%s <%s>\033[0m %s\n", timestr, levels[LOG_ERR], tmp);

    log2std(stderr, m);
}

int
logger_init(int syslog, int level) {
    char *env_logformat = getenv("LOGFORMAT");
    if (env_logformat != NULL && strcmp("0", env_logformat) == 0) {
        _clean = 1;
    }
    _syslog = syslog;
    _level = level;
    return 0;
}
