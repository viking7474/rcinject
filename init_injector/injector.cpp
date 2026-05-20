#include "logging.hpp"

#include "elf_parser.hpp"
#include "maps_scan.hpp"
#include "misc.hpp"
#include "ptrace_utils.hpp"
#include "result.hpp"
#include <asm-generic/signal.h>
#include <asm/fcntl.h>
#include <asm/unistd_64.h>
#include <bits/wait.h>
#include <cstdlib>
#include <dlfcn.h>
#include <linux/ptrace.h>
#include <set>
#include <sys/user.h>
#include <unistd.h>

Result<Void> inject_init(const std::string& rc_content, std::string_view inject_lib_path, int pid = 1, bool do_in_child = false) {
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD) < 0) {
        return Errno(Format("seize {}", pid));
    }

    LOGD("attached");

    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) < 0) {
        return Errno("interrupt");
    }

    LOGD("interrupted");

    TRY(wait_for_trace(pid));

    LOGD("waited");

    run_finally detach{[&]() {
        if (ptrace(PTRACE_DETACH, pid, 0, 0) < 0) {
            PLOGE("detach");
        }
    }};

    // just used to stop at syscall
    SyscallInvoker si{pid};
    TRY(si.initialize(__NR_epoll_pwait));
    LOGI("stopped at syscall");
    run_finally restore_si{[&]() {
        if (auto res = si.restore(); res.is_err()) {
            LOGE("failed to restore: {}", res.get_error().display());
        }
    }};
    if (do_in_child) {
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK|PTRACE_O_TRACESYSGOOD) < 0) {
            PLOGE("traceclone opt");
        }
        TRY(si.do_syscall_pre(__NR_clone, SIGCHLD, 0, 0, 0, 0));
        auto status = TRY(wait_for_trace(pid));
        int new_pid;
        if (status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))) {
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) < 0) {
                return Errno("get new pid");
            }
            LOGD("new pid {}", new_pid);
        } else {
            return Err(Format("unexpected status: {}", parse_status(status)));
        }
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            return Errno("ptrace_syscall after clone event");
        }
        TRY(si.do_syscall_post());
        restore_si.run_now();
        detach.run_now();
        pid = new_pid;

        status = TRY(wait_for_trace(pid));
        LOGD("new pid status: {}", parse_status(status));
        getchar();
    }

    run_finally freeze_child{[&]() {
        if (do_in_child) {
            if (kill(pid, SIGSTOP) < 0) {
                PLOGE("could not kill stop");
            }
            if (ptrace(PTRACE_DETACH, pid, 0, SIGSTOP) < 0) {
                PLOGE("could not detach");
            }
        }
    }};


    struct user_regs_struct regs{}, backup{};
    TRY(get_regs(pid, regs));
    memcpy(&backup, &regs, sizeof(regs));

    uintptr_t libdl_base = 0;
    std::string libdl_path;
    uintptr_t libc_base = 0;
    std::string libc_path;

    maps_scan::MapInfo::ForEach([&](const maps_scan::MapInfo &info) -> bool {
        if (info.offset == 0) {
            if (!libdl_base && info.path.ends_with("/libdl.so")) {
                libdl_path = info.path;
                libdl_base = info.start;
            } else if (!libc_base && info.path.ends_with("/libc.so")) {
                libc_path = info.path;
                libc_base = info.start;
            }
        }
        return !libdl_base || !libc_base;
    }, std::to_string(pid));

    if (!libdl_base) {
        LOGE("no libdl found");
        return Err("no libdl found");
    }

    LOGI("libdl {} {:x}", libdl_path, libdl_base);

    elf_parser::Elf libdl{};
    if (!libdl.InitFromFile(libdl_path, libdl_base, true)) {
        return Err("init elf");
    }

    auto dlopen_addr = (uintptr_t) libdl.getSymbAddress("dlopen");
    auto dlclose_addr = (uintptr_t) libdl.getSymbAddress("dlclose");
    auto dlsym_addr = (uintptr_t) libdl.getSymbAddress("dlsym");

    set_system_con(inject_lib_path);
    auto lib_path = TRY(push_string(pid, regs, inject_lib_path));

    uintptr_t args[] = {lib_path, RTLD_NOW};

    auto calldlerr = [&]() -> Result<Void> {
        auto dlerror_addr = (uintptr_t) libdl.getSymbAddress("dlerror");
        auto err_str = TRY(remote_call(pid, regs, dlerror_addr, 0, nullptr, 0).context("get dlerror"));
        LOGD("dlerror got {:x}", err_str);
        auto errs = TRY(read_proc_str(pid, err_str));
        LOGE("dlerror: {}", errs);
        return Ok();
    };

    auto handle = TRY(remote_call(pid, regs, dlopen_addr, 0, args, 2).context("dlopen"));
    if (handle == 0) {
        if (auto res = calldlerr(); res.is_err()) {
            LOGE("calldlerr err: {}", res.get_error().display());
        }
        return Err("dlopen");
    }

    LOGD("opened {:x}", handle);

    std::set<int> remote_kmsg_fds{};
    {
        auto dir = xopen_dir(Format("/proc/{}/fd", pid).c_str());
        if (!dir) {
            LOGE("could not open fd dir");
        } else {
            for (dirent *entry; (entry = readdir(dir.get()));) {
                if (entry->d_type != DT_LNK) continue;
                auto p = read_link(Format("/proc/{}/fd/{}", pid, entry->d_name));
                if (p == "/dev/kmsg") {
                    auto kmsg_fd = (int) strtoul(entry->d_name, nullptr, 0);
                    remote_kmsg_fds.insert(kmsg_fd);
                    LOGD("found kmsg fd {}", kmsg_fd);
                }
            }
        }
    }
    if (remote_kmsg_fds.empty()) {
        LOGW("no kmsg fd found!");
    }

    auto callsym = [&]() -> Result<Void> {
        auto symstr = TRY(push_string(pid, regs, "Entry"));

        uintptr_t dlsym_args[] = {handle, symstr};

        auto fn = TRY(remote_call(pid, regs, dlsym_addr, 0, dlsym_args, 2));

        if (!fn) {
            if (auto res = calldlerr(); res.is_err()) {
                LOGE("calldlerr err: {}", res.get_error().display());
            }
            return Err("dlsym err");
        }

        TRY(remote_pre_call(pid, regs, fn, 0, nullptr, 0, false).context("call entry"));
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
            return Err("cont syscall");
        }
        int status;
        bool syscall_entered = false;
        for (;;) {
            struct user_regs_struct regs2;
            status = TRY(wait_for_trace(pid));
            if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)) {
                if (syscall_entered) {
                    syscall_entered = false;
                } else {
                    syscall_entered = true;
                    TRY(get_regs(pid, regs2));
                    //LOGD("nr: {}", regs2.REG_NR);
                    if (regs2.REG_NR == __NR_openat) {
                        // LOGD("opening flags={:x} filename={:x} fd={}", regs2.regs[2], regs2.regs[1], regs2.regs[0]);
                        if (auto openstr = read_proc_str(pid, regs2.regs[1]); openstr.is_ok()) {
                            // LOGD("opening {}", openstr.get_value());
                            auto val = openstr.get_value();
                            if (val.starts_with("/proc/self/fd/")) {
                                LOGI("found memfd, write rc content");
                                auto fdnum = val.substr(sizeof("/proc/self/fd/") - 1);
                                auto wf = xopen_file(Format("/proc/{}/fd/{}", pid, fdnum).c_str(), "w");
                                if (!wf) {
                                    LOGE("could not open memfd!");
                                } else {
                                    if (fwrite(rc_content.data(), rc_content.size(), 1, wf.get()) != 1) {
                                        PLOGE("not fully written rc content");
                                    }
                                }
                            }
                        } else {
                            LOGE("could not read openstr: {}", openstr.get_error().display());
                        }
                        if (regs2.regs[2] & O_NOFOLLOW) {
                            LOGD("fix O_NOFOLLOW");
                            regs2.regs[2] &= ~O_NOFOLLOW;
                            TRY(set_regs(pid, regs2));
                        }
                    } else if (regs2.REG_NR == __NR_write) {
                        auto fd = (int) regs2.regs[0];
                        if (remote_kmsg_fds.contains(fd)) {
                            auto remote_str = regs2.regs[1];
                            auto remote_len = regs2.regs[2];
                            std::string local_str{};
                            local_str.resize(remote_len);
                            if (auto r = read_proc(pid, remote_str, local_str.data(), remote_len); r.is_ok()) {
                                LOGD("remote log: {}", local_str);
                            } else {
                                LOGE("failed to get remote log: {}", r.get_error().display());
                            }
                        }
                    }
                }
                if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
                    return Err("cont syscall");
                }
            } else {
                // LOGW("other sig: {}", parse_status(status));
                break;
            }
        }
        auto res = TRY(remote_post_call(pid, regs, 0, status));
        if (res == 0) {
            LOGD("remote call entry success");
        } else {
            LOGE("call entry failed: res {}", res);
        }

        return Ok();
    };

    if (auto res = callsym(); res.is_err()) {
        LOGE("call sym err: {}", res.get_error().display());
        if (do_in_child)
            return res;
    }

    uintptr_t close_args[] = {handle};

    TRY(remote_call(pid, regs, dlclose_addr, 0, close_args, 1).context("dlclose"));

    LOGD("closed");

    freeze_child.disable();

    return Ok();
}

int main(int argc, char **argv) {
    logging::setPrintEnabled(true);
    int pid = 1;
    bool do_in_fork = false;
    std::string rc_file, lib_path = "/data/local/tmp/libinjectrclib.so";
    if (argc >= 2) {
        for (int i = 1; i < argc; i++) {
            std::string_view a{argv[i]};
            if (!a.starts_with("-")) {
                LOGD("opening {}", argv[i]);
                auto f = xopen_file(argv[i], "r");
                if (f) {   
                    char buf[4096];
                    size_t l = 0;
                    for (;;) {
                        auto r = fread(buf, 1, sizeof(buf), f.get());
                        if (r == 0) break;
                        l += r;
                        rc_file.append(buf, r);
                    }
                    LOGI("imported {} {} bytes", argv[i], l);
                }
            } else if ((i + 1) < argc) {
                if (a == "--pid" || a == "-p") {
                    pid = strtoul(argv[++i], nullptr, 0);
                } else if (a == "--lib") {
                    lib_path = argv[++i];
                }
            } else if (a == "--fork") {
                do_in_fork = true;
            }
        }
        LOGD("tracing {}", pid);
    } else {
        LOGI("usage: <rcfile [rcfiles...]> [--pid|-p pid] [--fork] [--lib]");
        return 1;
    }
    if (rc_file.empty()) {
        LOGE("no rc to inject!");
        return 1;
    }
    block_sigchld();
    auto res = inject_init(rc_file, lib_path, pid, do_in_fork);
    unblock_sigchld();
    if (res.is_err()) {
        LOGE("inject err: {}", res.get_error().display());
        return 1;
    }
    return 0;
}
