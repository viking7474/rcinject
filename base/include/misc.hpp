#pragma once

#include <cstddef>
#include <iterator>
#include <string>
#include <unistd.h>
#include <functional>
#include <dirent.h>

#include "fmt/format.h"

#if defined(__LP64__)
#define LP_SELECT(lp32, lp64) lp64
#else
#define LP_SELECT(lp32, lp64) lp32
#endif

class UniqueFd {
    using Fd = int;

public:
    UniqueFd() = default;

    inline UniqueFd(Fd fd) : fd_(fd) {}

    inline ~UniqueFd() {
        if (fd_ >= 0) close(fd_);
    }

    // Disallow copy
    inline UniqueFd(const UniqueFd &) = delete;

    inline UniqueFd &operator=(const UniqueFd &) = delete;

    inline bool valid() const { return fd_ >= 0; }

    inline void drop() {
        if (valid()) close(fd_);
        fd_ = -1;
    }

    // Allow move
    inline UniqueFd(UniqueFd &&other) {
        drop();
        std::swap(fd_, other.fd_);
    }

    inline UniqueFd &operator=(UniqueFd &&other) {
        drop();
        std::swap(fd_, other.fd_);
        return *this;
    }

    inline int into_fd() {
        int r = -1;
        std::swap(r, fd_);
        return r;
    }

    inline int as_fd() const { return fd_; }

    // Implict cast to Fd
    inline operator const Fd &() const { return fd_; }

private:
    Fd fd_ = -1;
};

template <typename... T>
inline std::string Format(fmt::format_string<T...> fmt, T... args) {
    std::string res;
    fmt::format_to(std::back_inserter(res), fmt, std::forward<T>(args)...);
    return res;
}

template <typename... T>
inline void fprint(FILE *f, fmt::format_string<T...> fmt, T... args) {
    std::string res;
    fmt::format_to(std::back_inserter(res), fmt, std::forward<T>(args)...);
    fwrite(res.data(), res.size(), 1, f);
}

template <typename... T>
inline void print(fmt::format_string<T...> fmt, T... args) {
    fprint(stdout, fmt, std::forward<T>(args)...);
}

std::string hexdump(void *addr, size_t sz, uintptr_t base = 0, bool dump_base = false);

struct timespec operator-(const timespec &t1, const timespec &t2);
struct timespec operator+(const timespec &t1, const timespec &t2);

int setfilecon(const char *path, const char *con);

int fsetfilecon(int fd, const char *con);

using sFILE = std::unique_ptr<FILE, decltype(&fclose)>;
using sDIR = std::unique_ptr<DIR, decltype(&closedir)>;
std::string getfilecon(const char *path);
sFILE make_file(FILE *fp);
sDIR make_dir(DIR *dp);
FILE *xfopen(const char *path, const char *mode);
DIR *xopendir(const char *path);
static inline sFILE xopen_file(const char *path, const char *mode) {
    return make_file(xfopen(path, mode));
}

static inline sDIR xopen_dir(const char *path) { return make_dir(xopendir(path)); }

class run_finally {
    std::function<void()> fn_;
    bool disabled = false;

public:
    inline run_finally(std::function<void()> fn) : fn_(fn) {}

    inline void disable() { disabled = true; }

    inline ~run_finally() {
        if (!disabled) fn_();
    }

    inline void run_now() {
        fn_();
        fn_ = nullptr;
        disabled = true;
    }
};

std::string read_link(std::string_view path);
