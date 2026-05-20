#include "ptrace_utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "logging.hpp"
#include "misc.hpp"

Result<Void> write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len,
                        bool use_proc_mem) {
    LOGV("write to {} addr 0x{:x} size {} use_proc_mem={}", pid, remote_addr, len, use_proc_mem);
    if (use_proc_mem) {
        auto path = Format("/proc/{}/mem", pid);
        UniqueFd fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd == -1) {
            return Errno("open proc mem");
        }
        while (len > 0) {
            auto l = TEMP_FAILURE_RETRY(pwrite64(fd, buf, len, remote_addr));
            if (l == -1) {
                return Errno(Format("write proc mem 0x{:x}", remote_addr));
            }
            len -= l;
            remote_addr += l;
        }
    } else {
        while (len > 0) {
            struct iovec local{.iov_base = (void *)buf, .iov_len = len};
            struct iovec remote{.iov_base = (void *)remote_addr, .iov_len = len};
            auto l = TEMP_FAILURE_RETRY(process_vm_writev(pid, &local, 1, &remote, 1, 0));
            if (l < 0) {
                return Errno(Format("process_vm_writev 0x{:x}+{}", remote_addr, len));
            } else {
                len -= l;
                remote_addr += l;
            }
        }
    }
    return Ok();
}

Result<std::string> read_proc_str(int pid, uintptr_t remote_addr) {
    std::string res{};
    char buf[256];
    size_t len = sizeof(len);
    auto p = remote_addr;
    for (;;) {
        struct iovec local{.iov_base = (void *)buf, .iov_len = len};
        struct iovec remote{.iov_base = (void *)p, .iov_len = len};
        auto l = TEMP_FAILURE_RETRY(process_vm_readv(pid, &local, 1, &remote, 1, 0));
        if (l < 0) {
            return Errno(Format("process_vm_readv 0x{:x}+{}", remote_addr, p - remote_addr));
        }
        if (res.size() > 512) {
            LOGE("too large: current:\n{}", hexdump(res.data(), res.size()));
            return Err("too large");
        }
        if (l == 0) {
            return Err(Format("truncated"));
        }
        int i;
        for (i = 0; i < l; i++) {
            if (buf[i] == 0) break;
        }
        res.append(buf, i);
        if (i != l) break;
        p += l;
    }
    return res;
}

Result<Void> read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    while (len > 0) {
        struct iovec local{.iov_base = (void *)buf, .iov_len = len};
        struct iovec remote{.iov_base = (void *)remote_addr, .iov_len = len};
        auto l = TEMP_FAILURE_RETRY(process_vm_readv(pid, &local, 1, &remote, 1, 0));
        if (l < 0) {
            return Errno(Format("process_vm_readv 0x{:x}+{}", remote_addr, len));
        }
        len -= l;
        remote_addr += l;
    }
    return Ok();
}

Result<Void> get_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        return Errno("getregs");
    }
#elif defined(__aarch64__) || defined(__arm__)
#if defined(__arm__)
    static bool use_getregs = false;
    if (use_getregs) {
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            return Errno("getregs");
        } else {
            return Ok();
        }
    }
#endif
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
#if defined(__arm__)
        if (errno == EIO) {
            LOGW("GETREGSET failed, retry with GETREGS");
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
                use_getregs = true;
                return Ok();
            }
        }
#endif
        return Errno("getregs");
    }
#endif
    return Ok();
}

Result<Void> set_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        return Errno("setregs");
    }
#elif defined(__aarch64__) || defined(__arm__)
#if defined(__arm__)
    static bool use_setregs = false;
    if (use_setregs) {
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            return Errno("setregs");
        } else {
            return Ok();
        }
    }
#endif
    struct iovec iov = {
        .iov_base = &regs,
        .iov_len = sizeof(struct user_regs_struct),
    };
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
#if defined(__arm__)
        if (errno == EIO) {
            LOGW("SETREGSET failed, retry with SETREGS");
            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == 0) {
                use_setregs = true;
                return Ok();
            }
        }
#endif
        return Errno("setregs");
    }
#endif
    return Ok();
}

void align_stack(struct user_regs_struct &regs, uintptr_t preserve) {
    regs.REG_SP = (regs.REG_SP - preserve) & ~0xf;
}

Result<uintptr_t> push_memory(int pid, struct user_regs_struct &regs, void *local_addr,
                              size_t len) {
    regs.REG_SP -= len;
    align_stack(regs);
    auto addr = static_cast<uintptr_t>(regs.REG_SP);
    TRY(write_proc(pid, addr, local_addr, len).context("push_memory"));
    LOGV("pushed mem 0x{:x}", addr);
    return addr;
}

Result<uintptr_t> push_string(int pid, struct user_regs_struct &regs, std::string_view str) {
    auto len = str.size() + 1;
    regs.REG_SP -= len;
    align_stack(regs);
    auto addr = static_cast<uintptr_t>(regs.REG_SP);
    TRY(write_proc(pid, addr, str.data(), len).context("push_string"));
    LOGV("pushed string {} to 0x{:x}", str, addr);
    return addr;
}

Result<Void> remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                             uintptr_t return_addr, uintptr_t *args, size_t count, bool cont) {
#if defined(__aarch64__)
    // clear PSR_BTYPE_MASK to mock direct jump, thus satisfies BTI check
    // https://developer.arm.com/documentation/102433/0200/Jump-oriented-programming
    regs.pstate &= ~PSR_BTYPE_MASK;
#endif
    align_stack(regs);
    LOGV("calling remote function 0x{:x} {} args", func_addr, count);
#if defined(__x86_64__)
    if (count >= 1) {
        regs.rdi = args[0];
    }
    if (count >= 2) {
        regs.rsi = args[1];
    }
    if (count >= 3) {
        regs.rdx = args[2];
    }
    if (count >= 4) {
        regs.rcx = args[3];
    }
    if (count >= 5) {
        regs.r8 = args[4];
    }
    if (count >= 6) {
        regs.r9 = args[5];
    }
    if (count > 6) {
        auto remain = (count - 6) * sizeof(uintptr_t);
        align_stack(regs, remain);
        TRY(write_proc(pid, (uintptr_t)regs.REG_SP, args + 6, remain).context("remote_pre_call"));
    }
    regs.REG_SP -= sizeof(uintptr_t);
    TRY(write_proc(pid, (uintptr_t)regs.REG_SP, &return_addr, sizeof(return_addr))
            .context("write return addr"));
    regs.REG_IP = func_addr;
#elif defined(__i386__)
    if (count > 0) {
        auto remain = count * sizeof(uintptr_t);
        align_stack(regs, remain);
        TRY(write_proc(pid, (uintptr_t)regs.REG_SP, args, remain).context("remote_pre_call"));
    }
    regs.REG_SP -= sizeof(uintptr_t);
    TRY(write_proc(pid, (uintptr_t)regs.REG_SP, &return_addr, sizeof(return_addr)).context(""));
    regs.REG_IP = func_addr;
#elif defined(__aarch64__)
    for (size_t i = 0; i < count && i < 8; i++) {
        regs.regs[i] = args[i];
    }
    if (count > 8) {
        auto remain = (count - 8) * sizeof(uintptr_t);
        align_stack(regs, remain);
        TRY(write_proc(pid, (uintptr_t)regs.REG_SP, args + 8, remain).context("remote_pre_call"));
    }
    regs.regs[30] = return_addr;
    regs.REG_IP = func_addr;
#elif defined(__arm__)
    for (size_t i = 0; i < count && i < 4; i++) {
        regs.uregs[i] = args[i];
    }
    if (count > 4) {
        auto remain = (count - 4) * sizeof(uintptr_t);
        align_stack(regs, remain);
        TRY(write_proc(pid, (uintptr_t)regs.REG_SP, args + 4, remain).context("remote_pre_call"));
    }
    regs.uregs[14] = return_addr;
    regs.REG_IP = func_addr & ~1;
    if (func_addr & 1) {
        regs.REG_CPSR = regs.REG_CPSR | CPSR_T_MASK;
    } else {
        regs.REG_CPSR = regs.REG_CPSR & ~CPSR_T_MASK;
    }
#endif
    TRY(set_regs(pid, regs).context("remote_pre_call"));
    if (cont && ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        return Errno("ptrace_cont");
    }
    return Ok();
}

Result<uintptr_t> remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t return_addr, int given_status) {
    auto status = given_status == -1 ? TRY(wait_for_trace(pid)) : given_status;
    TRY(get_regs(pid, regs).context("remote_post_call"));
    auto stop_sig = WSTOPSIG(status);
    if (WSTOPSIG(status) == SIGSEGV) {
        if (static_cast<uintptr_t>(regs.REG_IP) == return_addr) {
            return regs.REG_RET;
        }
    }

    LOGE("{} status={} addr={}",
        stop_sig == SIGSEGV ? "wrong return addr" : "stopped by other reason",
        parse_status(status), (void *)regs.REG_IP
    );

    siginfo_t siginfo;
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
        PLOGE("failed to get siginfo");
    } else {
        LOGE("si_code={} si_addr={}", siginfo.si_code, siginfo.si_addr);
    }

#if defined(__aarch64__)
    std::string s{};
    for (int i = 0; i < 31; i++) {
        s += Format("x{:02d} {:016x}", i, regs.regs[i]);
        if (i % 4 == 3) {
            s += '\n';
        } else {
            s += ' ';
        }
    }
    s += '\n';
    s += Format("sp {:016x} pc {:016x} pstate {:016x}\n", regs.sp, regs.pc, regs.pstate);
    LOGE("{}", s);

    char mem[64];
    if (auto res = read_proc(pid, regs.pc - 32, mem, sizeof(mem)); res.is_ok()) {
        auto dump = hexdump(mem, sizeof(mem), regs.pc - 32, true);
        LOGE("memory near pc:\n{}", dump);
    } else {
        LOGE("failed to dump remote mem: {}", res.get_error().display());
    }

    
#endif

    return Err(114, WSTOPSIG(status), "remote_post_call failed");
}

Result<uintptr_t> remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                              uintptr_t return_addr, uintptr_t *args, size_t count) {
    TRY(remote_pre_call(pid, regs, func_addr, return_addr, args, count).context("remote_call"));
    return TRY(remote_post_call(pid, regs, return_addr).context("remote_call"));
}

static Result<int> do_wait(pid_t pid, int flags) {
    int status = 0;
    pid_t result = TEMP_FAILURE_RETRY(waitpid(pid, &status, flags));
    if (result < 0) {
        return Errno(Format("waitpid {}", pid));
    }
    return status;
}

static Result<int> do_wait_timeout(pid_t pid, int flags, uint32_t timeout) {
    int status;
    sigset_t sigset;
    // if timeout is specified, wait with WNOHANG first
    // if nothing waited, wait for SIGCHLD with timeout and retry
    struct timespec to, duration;
    duration.tv_sec = timeout;
    duration.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &to);
    to = to + duration;
    flags |= WNOHANG;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    for (;;) {
        pid_t result = waitpid(pid, &status, flags);
        // wait for all children
        if (pid == -1) {
            while (result > 0) {
                LOGV("wait for all: {} exited: {}", result, parse_status(status));
                result = waitpid(pid, &status, flags);
            }
            if (result == -1 && errno == ECHILD) {
                LOGV("all children done");
                return 0;
            }
        }
        if (result == 0) {  // has child but not done
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            duration = to - now;
            if (duration.tv_sec < 0) {
                errno = EAGAIN;
                return Errno(Format("wait {} timeout", pid));
            }
            int sig = TEMP_FAILURE_RETRY(sigtimedwait(&sigset, nullptr, &duration));
            if (sig == -1) {
                if (errno == EAGAIN) return Errno(Format("wait {} timeout", pid));
                return Errno(Format("sigtimedwait when wait {}", pid));
            }
            continue;  // wait again
        } else if (pid == -1)
            continue;  // wait for all children
        if (result <= 0) {
            return Errno(Format("waitpid {}", pid));
        }
        return status;
    }
}

Result<int> wait_for_trace(pid_t pid, uint32_t timeout) {
    int status;
    if (timeout == 0)
        status = TRY(do_wait(pid, __WALL));
    else
        status = TRY(do_wait_timeout(pid, __WALL, timeout));
    if (!WIFSTOPPED(status)) {
        return Err(
            Format("process {} not stopped for trace: {}", pid, parse_status(status).c_str()));
    }
    return status;
}

Result<Void> ptrace_cont(int pid, int sig) {
    if (ptrace(PTRACE_CONT, pid, 0, sig) == -1) {
        return Err(Format("ptrace_cont pid={}, sig={}", pid, sig));
    }
    return Ok();
}

std::string parse_status(int status, int si_code) {
    if (si_code != 0) {
        switch (si_code) {
        case CLD_KILLED:
            return Format("signaled with {}", status);
            break;
        case CLD_DUMPED:
            return Format("signaled with {} (dumped)", status);
            break;
        case CLD_EXITED:
            return Format("exited with {}", status);
            break;
        default:
            return Format("unknown si_code={} status=0x{:x}", si_code, status);
        }
    } else if (WIFEXITED(status)) {
        return Format("0x{:x} exited with {}", status, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        return Format("0x{:x} signaled with {}({})", status, sigabbrev_np(WTERMSIG(status)),
                      WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        auto stop_sig = WSTOPSIG(status);
        return Format("0x{:x} stopped by signal={}({}),event={}", status, sigabbrev_np(stop_sig),
                      stop_sig, parse_ptrace_event(status));
    } else {
        return Format("0x{:x} unknown", status);
    }
}

std::string get_program(int pid) {
    std::string path = "/proc/";
    path += std::to_string(pid);
    path += "/exe";
    constexpr const auto SIZE = 256;
    char buf[SIZE + 1];
    auto sz = readlink(path.c_str(), buf, SIZE);
    if (sz == -1) {
        PLOGE("readlink /proc/{}/exe", pid);
        return "";
    }
    buf[sz] = 0;
    return buf;
}

#if !defined(__i386__)
// no signal will be delivered because we've blocked all signal
static Result<Void> wait_for_syscall(int pid) {
    int status;
    for (;;) {
        status = TRY(wait_for_trace(pid).context("wait_for_syscall"));
        if (WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80))
            break;
        else {
            std::string sig_info = "(no siginfo)";
            switch (WSTOPSIG(status)) {
            case SIGILL:
            case SIGFPE:
            case SIGSEGV:
            case SIGBUS:
            case SIGTRAP: {
                siginfo_t siginfo;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1) {
                    PLOGE("failed to get siginfo");
                } else {
                    sig_info = Format("si_code={} si_addr={} si_trapno={}", siginfo.si_code,
                                      siginfo.si_addr, siginfo.si_trapno);
                }
                break;
            }
            }
            return Err(Format("non syscall stop: {} {}", parse_status(status), sig_info));
        }
    }
    return Ok();
}

// stop at next syscall and skip it
Result<Void> SyscallInvoker::initialize(int expected_nr) {
    int orig_nr = kInvalidNr;
    uintptr_t syscall_insn_addr;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            return Errno("ptrace_syscall init pre");
        }
        TRY(wait_for_syscall(pid).context("initialize syscall pre"));

        // syscall entry

        TRY(get_regs(pid, regs).context("do_syscall"));
        memcpy(&backup, &regs, sizeof(struct user_regs_struct));
        LOGD("initialize syscall at nr={} 0x{:x}", static_cast<int>(regs.REG_NR),
            (uintptr_t)backup.REG_IP);
        syscall_insn_addr = regs.REG_IP;

        // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/arch/arm64/kernel/syscall.c;l=115;drc=7fe33e9f662c0a2f5110be4afff0a24e0c123540

        backup.REG_IP -= SYSCALL_INSN_SIZE(backup);
        
#if defined(__x86_64__)
        orig_nr = regs.orig_rax;
#else
        orig_nr = regs.REG_NR;
#endif

        if (expected_nr != -1 && orig_nr != expected_nr) {
            LOGD("expected nr {} current {}, skip", expected_nr, orig_nr);
            continue;
        }
        break;
    }

#if defined(__x86_64__)
    backup.rax = regs.orig_rax;
    backup.orig_rax = -1;

    regs.REG_NR = kInvalidNr;
    TRY(set_regs(pid, regs).context("do_syscall"));
#endif

#if defined(__aarch64__)
    // or GET NT_ARM_SYSCALL ?
    // https://stackoverflow.com/questions/63620203/ptrace-change-syscall-number-arm64
    int syscallno = kInvalidNr;
    struct iovec iov = {
        .iov_base = &syscallno,
        .iov_len = sizeof(int),
    };
    if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_SYSTEM_CALL, &iov) == -1) {
        return Errno("set syscall");
    }
#endif

#if defined(__arm__)
    if (ptrace(PTRACE_SET_SYSCALL, pid, 0, kInvalidNr) == -1) {
        return Errno("set syscall");
    }
#endif

    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        return Errno("ptrace_syscall init post");
    }

    TRY(wait_for_syscall(pid).context("initialize syscall post"));
    TRY(get_regs(pid, regs));

    // check if it is really skipped
    if (  // regs.REG_RET != -ENOSYS ||
          // this is only valid on x86, not on arm64
          // https://cs.android.com/android/kernel/superproject/+/common-android-mainline:common/arch/arm64/kernel/syscall.c;l=127;drc=7fe33e9f662c0a2f5110be4afff0a24e0c123540
        regs.REG_IP != syscall_insn_addr) {
        return Err(
            Format("unexpected ret=0x{:x}, pc=0x{:x}, when skip nr={} "
                   "expected 0x{:x}, 0x{:x}",
                   (uintptr_t)regs.REG_RET, (uintptr_t)regs.REG_IP, orig_nr,
                   static_cast<uintptr_t>(-ENOSYS), syscall_insn_addr));
    }

    insn_addr = syscall_insn_addr;

    return Ok();
}

Result<Void> SyscallInvoker::do_syscall_pre(int nr, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
                                            uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {
    current_nr = nr;
    memcpy(&regs, &backup, sizeof(struct user_regs_struct));
    LOGV(
        "do syscall pre: nr={} pc=0x{:x} arg0=0x{:x} arg1=0x{:x} arg2=0x{:x} "
        "arg3=0x{:x} arg4=0x{:x} arg5=0x{:x}",
        nr, (uintptr_t)regs.REG_IP, arg0, arg1, arg2, arg3, arg4, arg5);
    // set syscall nr and args
    regs.REG_WNR = nr;

#if defined(__aarch64__)
    regs.regs[0] = arg0;
    regs.regs[1] = arg1;
    regs.regs[2] = arg2;
    regs.regs[3] = arg3;
    regs.regs[4] = arg4;
    regs.regs[5] = arg5;
#endif

#if defined(__arm__)
    regs.uregs[0] = arg0;
    regs.uregs[1] = arg1;
    regs.uregs[2] = arg2;
    regs.uregs[3] = arg3;
    regs.uregs[4] = arg4;
    regs.uregs[5] = arg5;
#endif

#if defined(__x86_64__)
    regs.rdi = arg0;
    regs.rsi = arg1;
    regs.rdx = arg2;
    regs.r10 = arg3;
    regs.r8 = arg4;
    regs.r9 = arg5;
#endif
    TRY(set_regs(pid, regs));

    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        return Errno("ptrace_syscall pre");
    }
    TRY(wait_for_syscall(pid));
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        return Errno("ptrace_syscall post");
    }
    return Ok();
}

Result<uintptr_t> SyscallInvoker::do_syscall_post(bool retry) {
    uintptr_t result = 0;

    if (retry) {
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            return Errno("ptrace_syscall retry");
        }
        TRY(wait_for_syscall(pid));
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            return Errno("ptrace_syscall post");
        }
    }

    TRY(wait_for_trace(pid).context("do_syscall"));
    TRY(get_regs(pid, regs).context("do_syscall"));

    result = regs.REG_RET;

    if (regs.REG_IP != insn_addr) {
        return Err(Format("ret=0x{:x}but got unexpected pc=0x{:x}, expected 0x{:x}",
                          (uintptr_t)regs.REG_RET, (uintptr_t)regs.REG_IP, insn_addr));
    }

    return result;
}

Result<uintptr_t> SyscallInvoker::do_syscall(int nr, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
                                             uintptr_t arg3, uintptr_t arg4, uintptr_t arg5) {
    TRY(do_syscall_pre(nr, arg0, arg1, arg2, arg3, arg4, arg5));
    return TRY(do_syscall_post());
}

Result<Void> SyscallInvoker::restore() {
    if (insn_addr != kUninitialized) return set_regs(pid, backup);
    return Ok();
}

#endif  // i386

int wait_for_child(int pid, uint32_t timeout) {
    Result<int> r;
    if (timeout == 0)
        r = do_wait(pid, 0);
    else
        r = do_wait_timeout(pid, 0, timeout);
    if (r.is_err()) {
        LOGE("wait for child {} err: {}", pid, r.get_error().display());
        auto e = r.get_error();
        if (e.sub_code == EAGAIN) return -2;
        return -1;
    }
    return r.get_value();
}

int get_elf_class(std::string_view path) {
    auto f = xopen_file(path.data(), "r");
    if (!f) return 0;
    unsigned char e_ident[EI_NIDENT];
    if (fread(e_ident, sizeof(e_ident), 1, f.get()) != 1) return 0;
    if (0 != memcmp(e_ident, ELFMAG, SELFMAG)) return 0;
    if (ELFCLASS64 != e_ident[EI_CLASS] && ELFCLASS32 != e_ident[EI_CLASS]) return 0;
    if (ELFDATA2LSB != e_ident[EI_DATA]) return 0;
    if (EV_CURRENT != e_ident[EI_VERSION]) return 0;
    fseek(f.get(), 0, SEEK_SET);
#if defined(__aarch64__) || defined(__arm__)
    constexpr const auto machine_64 = EM_AARCH64;
    constexpr const auto machine_32 = EM_ARM;
#elif defined(__x86_64__) || defined(__i386__)
    constexpr const auto machine_64 = EM_X86_64;
    constexpr const auto machine_32 = EM_386;
#endif
    if (ELFCLASS64 == e_ident[EI_CLASS]) {
        Elf64_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, f.get()) != 1) return 0;
        if (ET_DYN != ehdr.e_type) {
            LOGE("not dyn: {}", path);
            return 0;
        }
        if (ehdr.e_machine == machine_64) return 64;
        LOGE("unsupported machine {}", ehdr.e_machine);
    } else {
        Elf32_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, f.get()) != 1) return 0;
        if (ET_DYN != ehdr.e_type) {
            LOGE("not dyn: {}", path);
            return 0;
        }
        if (ehdr.e_machine == machine_32) return 32;
        LOGE("unsupported machine {}", ehdr.e_machine);
    }
    return 0;
}

void block_sigchld() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    if (pthread_sigmask(SIG_BLOCK, &sigset, nullptr) != 0) {
        PLOGE("block_sigchld");
    }
}

void unblock_sigchld() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);
    if (pthread_sigmask(SIG_UNBLOCK, &sigset, nullptr) != 0) {
        PLOGE("unblock_sigchld");
    }
}

static const std::string &get_system_con() {
    static std::string libc_con;
    if (libc_con.empty()) libc_con = getfilecon("/system/" LP_SELECT("lib", "lib64") "/libc.so");
    if (libc_con.empty()) libc_con = "u:object_r:system_file:s0";
    return libc_con;
}

bool set_system_con(std::string_view path) {
    if (setfilecon(path.data(), get_system_con().c_str()) == -1) {
        PLOGE("setcon {}", path);
        return false;
    }
    return true;
}

bool set_system_con(int fd) {
    if (fsetfilecon(fd, get_system_con().c_str()) == -1) {
        return false;
    }
    return true;
}
