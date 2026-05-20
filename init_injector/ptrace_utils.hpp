#pragma once
#include <sys/ptrace.h>

#include <string>
#include <unistd.h>

#include "result.hpp"

#ifdef __LP64__
#define ELFAFMT "llx"
#define ELFOFMT "llu"
#else
#define ELFAFMT "x"
#define ELFOFMT "u"
#endif

constexpr const auto NOT_IMPLEMENTED_ERROR = 2;
constexpr const auto REMOTE_ERROR = 3;

constexpr auto DEFAULT_TIMEOUT = 10;

#define SYSCALL_IS_ERR(e) (((unsigned long)e) > -4096UL)
#define SYSCALL_ERR(e) (-(int)(e))

#if defined(__x86_64__)
#define REG_SP rsp
#define REG_IP rip
#define REG_RET rax
// register of nr reading from syscall-enter
#define REG_NR orig_rax
#define REG_SYS_ARG0 rdi
// register of nr as argument of syscall insn
#define REG_WNR rax
#define SYSCALL_INSN_SIZE(_regs) 2
#elif defined(__i386__)
#define REG_SP esp
#define REG_IP eip
#define REG_RET eax
#define REG_NR orig_eax
#define REG_SYS_ARG0 ebx
#define REG_WNR eax
#define SYSCALL_INSN_SIZE(_regs) 2
#elif defined(__aarch64__)
#define REG_SP sp
#define REG_IP pc
#define REG_RET regs[0]
#define REG_NR regs[8]
#define REG_SYS_ARG0 regs[0]
#define REG_WNR REG_NR
#define SYSCALL_INSN_SIZE(_regs) 4
#elif defined(__arm__)
#define REG_SP uregs[13]
#define REG_IP uregs[15]
#define REG_RET uregs[0]
#define REG_NR uregs[7]
#define REG_SYS_ARG0 uregs[0]
#define REG_WNR REG_NR
#define user_regs_struct user_regs
#define SYS_mmap SYS_mmap2

#define REG_CPSR uregs[16]
#define CPSR_T_MASK (1lu << 5)
#define IS_THUMB(regs) (((regs).REG_CPSR & CPSR_T_MASK) != 0)
#define SYSCALL_INSN_SIZE(regs) (IS_THUMB(regs) ? 2 : 4)
#endif

Result<Void> write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len,
                        bool use_proc_mem = false);

Result<Void> read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

Result<std::string> read_proc_str(int pid, uintptr_t remote_addr);

Result<Void> get_regs(int pid, struct user_regs_struct &regs);

Result<Void> set_regs(int pid, struct user_regs_struct &regs);

void align_stack(struct user_regs_struct &regs, uintptr_t preserve = 0);

Result<uintptr_t> push_memory(int pid, struct user_regs_struct &regs, void *local_addr, size_t len);

Result<uintptr_t> push_string(int pid, struct user_regs_struct &regs, std::string_view str);

Result<uintptr_t> remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                              uintptr_t return_addr, uintptr_t *args, size_t count);

Result<int> wait_for_trace(pid_t pid, uint32_t timeout = DEFAULT_TIMEOUT);
Result<Void> ptrace_cont(int pid, int sig = 0);

std::string parse_status(int status, int si_code = 0);

#define WPTEVENT(x) (x >> 16)

#define CASE_CONST_RETURN(x)                                                                       \
    case x:                                                                                        \
        return #x;

inline const char *parse_ptrace_event(int status) {
    status = status >> 16;
    switch (status) {
        CASE_CONST_RETURN(PTRACE_EVENT_FORK)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
        CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
        CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
        CASE_CONST_RETURN(PTRACE_EVENT_STOP)
    default:
        return "(no event)";
    }
}

inline const char *sigabbrev_np(int sig) {
    if (sig > 0 && sig < NSIG) return sys_signame[sig];
    return "(unknown)";
}

std::string get_program(int pid);

#if !defined(__i386__)
class SyscallInvoker {
private:
    // kInvalidNr: an invalid syscall number to skip syscall
#if defined(__arm__)
    // On 32bit kernel (4.9), ptrace-syscall-exit will not be issued if scno ==
    // -1, but on 64bit kernel it will, so we use a different value to ensure
    // ptrace-syscall-exit is issued in both cases. see:
    // https://elixir.bootlin.com/linux/v4.9.117/source/arch/arm/kernel/entry-common.S#L269
    // and:
    // https://elixir.bootlin.com/linux/v4.9.117/source/arch/arm64/kernel/entry.S#L876
    // On kernel 3.4 of arm, ptrace-syscall-exit will be issued normally when
    // scno == -1. However if we use kInvalidNr = -2, the process will receive
    // SIGSEGV (si_code=SI_KERNEL, si_addr=0) after ptrace-syscall-exit. I can't
    // figure out the reason. I think it may be caused by arm_syscall, so use
    // 0xffff which should be a value not in range of arm syscalls see:
    // https://elixir.bootlin.com/linux/v3.4.113/source/arch/arm/kernel/entry-common.S#L466
    // and:
    // https://elixir.bootlin.com/linux/v3.4.113/source/arch/arm/kernel/traps.c#L512
    static constexpr const auto kInvalidNr = 0xffff;
#else
    static constexpr const auto kInvalidNr = -1;
#endif
    static constexpr const auto kUninitialized = static_cast<uintptr_t>(-1);

    int pid;
    int current_nr = kInvalidNr;
    struct user_regs_struct backup{};
    struct user_regs_struct regs{};
    uintptr_t insn_addr = kUninitialized;

public:
    SyscallInvoker(int p) : pid(p) {}

    Result<Void> initialize(int expected_nr = -1);

    Result<uintptr_t> do_syscall(int nr, uintptr_t arg0 = 0, uintptr_t arg1 = 0, uintptr_t arg2 = 0,
                                 uintptr_t arg3 = 0, uintptr_t arg4 = 0, uintptr_t arg5 = 0);
    Result<Void> do_syscall_pre(int nr, uintptr_t arg0 = 0, uintptr_t arg1 = 0, uintptr_t arg2 = 0,
                                uintptr_t arg3 = 0, uintptr_t arg4 = 0, uintptr_t arg5 = 0);
    Result<uintptr_t> do_syscall_post(bool retry = false);

    Result<Void> restore();
};
#endif

int wait_for_child(int pid, uint32_t timeout = 0);
int get_elf_class(std::string_view path);

Result<Void> remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr,
                             uintptr_t return_addr, uintptr_t *args, size_t count,
                             bool cont = true);

Result<uintptr_t> remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t return_addr, int given_status = -1);

void block_sigchld();
void unblock_sigchld();

bool set_system_con(std::string_view path);
bool set_system_con(int fd);

// elf loader

// Returns the address of the page containing address 'x'.
inline uintptr_t page_start(uintptr_t x) { return x & ~(getpagesize() - 1); }

// Returns the offset of address 'x' in its page.
inline uintptr_t page_offset(uintptr_t x) { return x & (getpagesize() - 1); }

// Returns the address of the next page after address 'x', unless 'x' is
// itself at the start of a page.
inline uintptr_t page_end(uintptr_t x) { return page_start(x + getpagesize() - 1); }

#define MAYBE_MAP_FLAG(x, from, to) (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)                                                                          \
    (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | MAYBE_MAP_FLAG((x), PF_R, PROT_READ) |                 \
     MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))
