#include "misc.hpp"

#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "logging.hpp"

std::string hexdump(void *addr, size_t sz, uintptr_t base, bool dump_base) {
    std::string ret;
    char buf[5];

    for (size_t i = 0; i < sz; i++) {
        if (dump_base && i % 16 == 0) {
            ret += Format("{:x} ", base);
        }
        snprintf(buf, sizeof(buf), "%02x", ((unsigned char *)addr)[i]);
        ret += buf;
        if (i % 16 == 15) {
            if (i != sz - 1) {
                ret += "\n";
            }
        } else {
            ret += " ";
        }
        base++;
    }

    return ret;
}

// only valid if t1 >= t2
struct timespec operator-(const timespec &t1, const timespec &t2) {
    auto s = t1.tv_sec - t2.tv_sec;
    auto ns = t1.tv_nsec - t2.tv_nsec;
    if (ns < 0) {
        ns += 1'000'000'000;
        s -= 1;
    }
    return {s, ns};
}

struct timespec operator+(const timespec &t1, const timespec &t2) {
    auto s = t1.tv_sec + t2.tv_sec;
    auto ns = t1.tv_nsec + t2.tv_nsec;
    if (ns >= 1'000'000'000) {
        ns -= 1'000'000'000;
        s += 1;
    }
    return {s, ns};
}

int setfilecon(const char *path, const char *con) {
    return syscall(__NR_setxattr, path, XATTR_NAME_SELINUX, con, strlen(con) + 1, 0);
}

int fsetfilecon(int fd, const char *con) {
    return syscall(__NR_fsetxattr, fd, XATTR_NAME_SELINUX, con, strlen(con) + 1, 0);
}

std::string getfilecon(const char *path) {
    char buf[1024];
    ssize_t sz = syscall(__NR_getxattr, path, XATTR_NAME_SELINUX, buf, sizeof(buf));
    if (sz == -1) {
        PLOGE("getfilecon {}", path);
        return "";
    }
    if (sz >= sizeof(buf)) {
        LOGE("filecon too big ({})", sz);
        errno = E2BIG;
    }
    buf[sz] = 0;
    return buf;
}

sFILE make_file(FILE *fp) {
    return sFILE(fp, [](FILE *fp) { return fp ? fclose(fp) : 1; });
}

sDIR make_dir(DIR *dp) {
    return sDIR(dp, [](DIR *dp) { return dp ? closedir(dp) : 1; });
}

FILE *xfopen(const char *path, const char *mode) {
    auto f = fopen(path, mode);
    if (!f) {
        PLOGE("fopen {}", path);
    }
    return f;
}

DIR *xopendir(const char *path) {
    auto dir = opendir(path);
    if (!dir) {
        PLOGE("opendir {}", path);
    }
    return dir;
}

std::string read_link(std::string_view path) {
    char buf[PATH_MAX];
    auto sz = readlink(path.data(), buf, PATH_MAX);
    if (sz < 0) {
        PLOGE("readlink {}", path);
    }
    return std::string{buf, (size_t) sz};
}
