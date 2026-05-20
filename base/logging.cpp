#include "logging.hpp"

#include <android/log.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>

#include "misc.hpp"

namespace logging {
FILE *klog = nullptr;

#define LOG_TAG "injectrc"
std::string tag = LOG_TAG;

bool use_print = false;
bool logging_enabled = true;
static char prio_str[] = {'V', 'D', 'I', 'W', 'E', 'F'};

void setLoggingEnabled(bool enabled) { logging_enabled = enabled; }

void setPrintEnabled(bool print) { use_print = print; }

void setTag(const char *t) { tag = t; }

void log_buf(int prio, const char *buf) {
    if (!logging_enabled) return;

    __android_log_write(prio, tag.c_str(), buf);

    if (use_print) {
        auto prio_char = (prio > ANDROID_LOG_DEFAULT && prio <= ANDROID_LOG_FATAL)
                             ? prio_str[prio - ANDROID_LOG_VERBOSE]
                             : '?';
        print("[{}][{}:{}][{}]:{}\n", prio_char, getpid(), gettid(), tag, buf);
    }
}
}  // namespace logging
