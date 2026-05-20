#pragma once

#include <android/log.h>

#include <array>
#include <cerrno>
#include <cstring>

#include "fmt/compile.h"
#include "fmt/format.h"

#define LOGI(fmt, args...) logging::log_fmt(ANDROID_LOG_INFO, fmt, ##args)
#define LOGW(fmt, args...) logging::log_fmt(ANDROID_LOG_WARN, fmt, ##args)
#define LOGE(fmt, args...) logging::log_fmt(ANDROID_LOG_ERROR, fmt, ##args)
#define PLOGE(fmt, args...) LOGE(fmt " failed with {}", ##args, errno)
#ifndef NODLOG
#define LOGD(fmt, args...) logging::log_fmt(ANDROID_LOG_DEBUG, fmt, ##args)
#define LOGV(fmt, args...) logging::log_fmt(ANDROID_LOG_VERBOSE, fmt, ##args)
#define PLOGEV(...) PLOGE(__VA_ARGS__)
#else
#define LOGD(...) 0
#define LOGV(...) 0
#define PLOGEV(...) 0
#endif

namespace logging {
void setTag(const char *tag);
void setPrintEnabled(bool print);
void setKlogEnabled(bool enabled);
void initLog();
void setLoggingEnabled(bool enabled);

void log_buf(int prio, const char *buf);

template <typename... T>
inline void log_fmt(int prio, fmt::format_string<T...> fmt, T &&...args) {
    std::array<char, 1024> buf;
    *fmt::format_to_n(buf.data(), buf.size() - 1, fmt, std::forward<T>(args)...).out = '\0';
    log_buf(prio, buf.data());
}

struct [[gnu::packed]] ZnLogTime {
    uint32_t sec;
    uint32_t nsec;
};

struct [[gnu::packed]] ZnLogHeader {
    ZnLogTime time;
    uint32_t tid;
    uint8_t prio;
};

void setZnLogEnabled(bool enabled);
void CloseZnLog();
void setZnLogKeepFd(bool keep);
int CurrentZnLogFd();
}  // namespace logging
