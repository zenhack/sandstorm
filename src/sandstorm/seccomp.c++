
#include <errno.h>
#include <sys/prctl.h>

// Used for various constants in the rules:
#include <linux/in.h>
#include <linux/tcp.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>

#include <sandstorm/seccomp.h>
#include <kj/debug.h>

// We need to define these constants before libseccomp has a chance to inject bogus
// values for them. See https://github.com/seccomp/libseccomp/issues/27
#ifndef __NR_seccomp
#define __NR_seccomp 317
#endif
#ifndef __NR_bpf
#define __NR_bpf 321
#endif
#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

#include <seccomp.h>

#define CHECK_SECCOMP(call)                   \
  do {                                        \
    if (auto result = (call)) {               \
      KJ_FAIL_SYSCALL(#call, -result);        \
    }                                         \
  } while (0)

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"  // SCMP_* macros produce these

namespace sandstorm {

void setupSeccompLegacy(bool devmode, bool dumpPfc) {
  // Install a rudimentary seccomp blacklist.
  // TODO(security): Change this to a whitelist.

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == nullptr)
    KJ_FAIL_SYSCALL("seccomp_init", 0);  // No real error code
  KJ_DEFER(seccomp_release(ctx));

  // Native code only for now, so there are no seccomp_arch_add calls.

  // Redundant, but this is standard and harmless.
  CHECK_SECCOMP(seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1));

  // It's easy to inadvertently issue an x32 syscall (e.g. syscall(-1)).  Such syscalls
  // should fail, but there's no need to kill the issuer.
  CHECK_SECCOMP(seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ERRNO(ENOSYS)));
  // Disable some things that seem scary.
  if (!devmode) {
    // ptrace is scary
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0));
  } else {
    // Try to be somewhat safe with ptrace in dev mode.  Note that the ability to modify
    // orig_ax using ptrace allows a complete seccomp bypass.
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 1,
      SCMP_A0(SCMP_CMP_EQ, PTRACE_POKEUSER)));
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 1,
      SCMP_A0(SCMP_CMP_EQ, PTRACE_SETREGS)));
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 1,
      SCMP_A0(SCMP_CMP_EQ, PTRACE_SETFPREGS)));
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 1,
      SCMP_A0(SCMP_CMP_EQ, PTRACE_SETREGSET)));
  }

  // Restrict the set of allowable network protocol families
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_GE, AF_NETLINK + 1)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_AX25)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_IPX)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_APPLETALK)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_NETROM)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_BRIDGE)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_ATMPVC)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_X25)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_ROSE)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_DECnet)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_NETBEUI)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_SECURITY)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A0(SCMP_CMP_EQ, AF_KEY)));

  // Disallow DCCP sockets due to Linux CVE-2017-6074.
  //
  // The `type` parameter to `socket()` can have SOCK_NONBLOCK and SOCK_CLOEXEC bitwise-or'd in,
  // so we need to mask those out for our check. The kernel defines a constant SOCK_TYPE_MASK
  // as 0x0f, but this constant doesn't appear to be in the headers, so we specify by hand.
  //
  // TODO(security): We should probably disallow everything except SOCK_STREAM and SOCK_DGRAM but
  //   I don't totally get how to write such conditionals with libseccomp. We should really dump
  //   libseccomp and write in BPF assembly, which is frankly much easier to understand.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPROTONOSUPPORT), SCMP_SYS(socket), 1,
     SCMP_A1(SCMP_CMP_MASKED_EQ, 0x0f, SOCK_DCCP)));

  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(add_key), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(request_key), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(keyctl), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(syslog), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(uselib), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(personality), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(acct), 0));

  // 16-bit code is unnecessary in the sandbox, and modify_ldt is a historic source
  // of interesting information leaks.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(modify_ldt), 0));

  // Despite existing at a 64-bit syscall, set_thread_area is only useful
  // for 32-bit programs.  64-bit programs use arch_prctl instead.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(set_thread_area), 0));

  // Disable namespaces. Nested sandboxing could be useful but the attack surface is large.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(unshare), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(mount), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(pivot_root), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(quotactl), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
      SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)));

  // AIO is scary.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_setup), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_destroy), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_getevents), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_submit), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(io_cancel), 0));

  // Scary vm syscalls
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(remap_file_pages), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(mbind), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(get_mempolicy), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(set_mempolicy), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(migrate_pages), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(move_pages), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(vmsplice), 0));

  // Scary futex operations
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(set_robust_list), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(get_robust_list), 0));

  // Utterly terrifying profiling operations
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(perf_event_open), 0));

  // Don't let apps specify their own seccomp filters, since seccomp filters are literally programs
  // that run in-kernel (albeit with a very limited instruction set).
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(prctl), 1,
      SCMP_A0(SCMP_CMP_EQ, PR_SET_SECCOMP)));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(seccomp), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(bpf), 0));

  // New syscalls that don't seem useful to Sandstorm apps therefore we will disallow them.
  // TODO(cleanup): Can we somehow specify "disallow all calls greater than N" to preemptively
  //   disable things until we've reviewed them?
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(userfaultfd), 0));

  // TOOD(someday): See if we can get away with turning off mincore, madvise, sysinfo etc.

  // TODO(someday): Turn off POSIX message queues and other such esoteric features.

  if (dumpPfc) {
    seccomp_export_pfc(ctx, 1);
  }

  CHECK_SECCOMP(seccomp_load(ctx));
}

void setupSeccompNew() {
  // Install a rudimentary seccomp whitelist.

  // Default action is to return ENOSYS. This is a good default though as
  // it means using applications using newer syscalls will behave just as
  // they would on an older kernel. Where we want to disallow something and
  // this behavior doesn't make sense, we try to override it to seem more
  // "natural," i.e. like something applications should be expected to
  // handle.
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
  //scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_LOG);
  if (ctx == nullptr)
    KJ_FAIL_SYSCALL("seccomp_init", 0);  // No real error code
  KJ_DEFER(seccomp_release(ctx));

  // Native code only for now, so there are no seccomp_arch_add calls.

  // Redundant, but this is standard and harmless.
  CHECK_SECCOMP(seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 1));

  // It's easy to inadvertently issue an x32 syscall (e.g. syscall(-1)).  Such syscalls
  // should fail, but there's no need to kill the issuer.
  CHECK_SECCOMP(seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ERRNO(ENOSYS)));

  // Boring and widely used syscalls:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(alarm), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chmod), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_gettime), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(creat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup3), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_create1), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_ctl), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_pwait), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(epoll_wait), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(eventfd2), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(faccessat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmodat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fdatasync), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(flock), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstatat64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgroups32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getitimer), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpgrp), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_add_watch), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_init1), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(inotify_rm_watch), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(link), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mremap), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(msync), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pause), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pread64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prlimit64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pwrite64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readv), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rmdir), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setitimer), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(signalfd4), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(symlink), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(umask), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0));

  // An older way of setting files to non-blocking mode:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
        SCMP_A1(SCMP_CMP_EQ, FIONBIO)));

  // TODO: Do we need shm*? I(zenhack) am under the impression that these are
  // emulated via mmap() in /dev/shm, but the syscall table does have numbers
  // for them...

  // TODO: whitelist the flags for mmap. Most of them are fine; as of
  // June 2020 the only really scary thing in the man page is
  // MAP_UNINITIALIZED, which is disabled (for obvious reasons) on all
  // stock distro kernels.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0));

  // TODO: can we restrict madvise? Many language runtimes use MADV_FREE
  // or MADV_DONTNEED to return memory to the OS, but it's likely we can
  // get away with just exposing a couple of the flags.
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0));

  // TODO: mprotect is fine from a sandbox-breakout perspective, but also
  // obviously rife for foot-shooting; are there particular dubious uses
  // we can block to protect apps from themselves without breaking things?
  // If not, maybe we could log them to make identifying apps doing stupid
  // things easier?
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0));

  // Allow creating sockets only for unix domain sockets, and tcp and udp
  // over ip. Other socket types are almost never needed or even useful,
  // and some have been a source of vulnerabilities in the past (e.g. DCCP
  // sockets due to Linux CVE-2017-6074).
  //
  // Writing this kind of conditional with libseccomp directly is confusing,
  // so we just generate the full combinatorial matrix ourselves; it isn't that big.
  for(int domain : {AF_UNIX, AF_INET, AF_INET6}) {
    for(int type : {SOCK_DGRAM, SOCK_STREAM}) {
      CHECK_SECCOMP(seccomp_rule_add(ctx,
        SCMP_ACT_ALLOW,
        SCMP_SYS(socket),
        2,
        SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)domain),
        // The `type` parameter to `socket()` can have SOCK_NONBLOCK and
        // SOCK_CLOEXEC bitwise-or'd in, so we need to mask those out for our
        // check. The kernel defines a constant SOCK_TYPE_MASK as 0x0f, but
        // this constant doesn't appear to be in the headers, so we specify
        // by hand.
        SCMP_A1(SCMP_CMP_MASKED_EQ, 0x0f, (scmp_datum_t)type)));
      CHECK_SECCOMP(seccomp_rule_add(ctx,
        SCMP_ACT_ALLOW,
        SCMP_SYS(socketpair),
        2,
        SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)domain),
        SCMP_A1(SCMP_CMP_MASKED_EQ, 0x0f, (scmp_datum_t)type)));
    }
  }

  // Whitelist specific socket options for {get,set}sockopt.
  for(int optname : {SO_ACCEPTCONN, SO_DOMAIN, SO_ERROR, SO_PROTOCOL, SO_TYPE,
                     SO_SNDLOWAT}) {
    // read only socket options.
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 2,
          SCMP_A1(SCMP_CMP_EQ, SOL_SOCKET),
          SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t)optname)));
  }
  for(int optname : {SO_BROADCAST, SO_KEEPALIVE, SO_LINGER, SO_OOBINLINE,
                     SO_REUSEADDR, SO_SNDBUF, SO_RCVBUF, SO_RCVTIMEO,
                     SO_SNDTIMEO, SO_RCVLOWAT}) {
    // read-write socket options for SOL_SOCKET.
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 2,
          SCMP_A1(SCMP_CMP_EQ, SOL_SOCKET),
          SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t)optname)));
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 2,
          SCMP_A1(SCMP_CMP_EQ, SOL_SOCKET),
          SCMP_A2(SCMP_CMP_EQ, (scmp_datum_t)optname)));
  }
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 2,
        SCMP_A1(SCMP_CMP_EQ, IPPROTO_TCP),
        SCMP_A2(SCMP_CMP_EQ, TCP_NODELAY)));

  // TODO: should we filter any of the flags for these?
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0));

  // Boring networking syscalls:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0));

  {
    auto allowed_clone_flags
      = CLONE_FILES
      | CLONE_PARENT
      | CLONE_SETTLS
      | CLONE_SIGHAND
      | CLONE_THREAD
      | CLONE_VFORK
      | CLONE_VM
      ;
    // Allow if masking out the above flags leaves the flags argument empty:
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
        SCMP_A2(SCMP_CMP_MASKED_EQ, (scmp_datum_t)allowed_clone_flags, 0)));
  }

  // Architecture specific whitelist; if we ever support non-x86_64 machines,
  // we will want to pay attention to this list:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0));

  // End whitelist.
  //
  // We have a some more rules below that don't allow additional access, but
  // cause some calls to be handled differently, e.g. reporting a different
  // error than ENOSYS

  // Performance hints, so it's safe to silently no-op these:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(0), SCMP_SYS(sched_yield), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(0), SCMP_SYS(fadvise64), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(0), SCMP_SYS(fadvise64_64), 0));

  // These would normally be denied without elevated privileges anyway, so return
  // the right error code:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chown), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chown32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchown), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchown32), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fchownat), 0));

  // Apps can reasonably be expected to handle these error codes:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(getxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(setxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(listxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(removexattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fgetxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fsetxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(flistxattr), 0));
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fremovexattr), 0));

  // This is the correct return code for an invalid ioctl:
  CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EINVAL), SCMP_SYS(ioctl), 0));

#if 0
  // Return ENOTTY for the most common tty ioctls. There are more listed in tty_ioctl(4),
  // but some of these seem to not have defined constants, or be of different types...
  // hopefully this list is good enough, the rest will hit the fallback rule.
  for(int cmd : {TCGETS, TCSETS, TCSETSW, TCSETSF,
                 TCGETA, TCSETA, TCSETAW, TCSETAF,
                 TIOCGLCKTRMIOS, TIOCSLCKTRMIOS,
                 TIOCGWINSZ, TIOCSWINSZ,
                 TCSBRK, TCSBRKP, TIOCCBRK,
                 TCXONC,
                 FIONREAD, TIOCINQ, TIOCOUTQ, TCFLSH,
                 TIOCSTI,
                 TIOCCONS,
                 TIOCSCTTY, TIOCNOTTY,
                 TIOCSPGRP, TIOCGSID,
                 TIOCEXCL, TIOCNXCL,
                 TIOCGETD, TIOCSETD,
                 }) {
    CHECK_SECCOMP(seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTTY), SCMP_SYS(ioctl), 1,
          SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)cmd)));
  }
#endif
}


#pragma GCC diagnostic pop
#undef CHECK_SECCOMP
};
