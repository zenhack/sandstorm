#include <unistd.h>
#include <signal.h>

#include "control-socket.h"
#include "util.h"

namespace sandstorm {
  class FdWrapper : public FileDescriptor::Server {
    public:
      FdWrapper(kj::AutoCloseFd&& fd): fd(kj::mv(fd)) {}
      FdWrapper(int fd): fd(fd) {}

      kj::Maybe<int> getFd() override {
        int ret = fd.get();
        if(ret < 0) {
          return nullptr;
        }
        return ret;
      }
    private:
      kj::AutoCloseFd fd;
  };

  FileDescriptor::Client exportFd(kj::AutoCloseFd&& fd) {
    return FileDescriptor::Client(kj::heap<FdWrapper>(kj::mv(fd)));
  }

  ControllerImpl::ControllerImpl(
        pid_t serverMonitorPid,
        kj::Own<ShellFDs::Reader>&& shellFds)
      : serverMonitorPid(serverMonitorPid),
        shellFds(kj::mv(shellFds)) {}


  kj::Promise<void> ControllerImpl::devShell(DevShellContext context) {
    // First make sure the shell is not running. Send the magic signal to the server monitor
    // to request this, and wait for the response signal SIGUSR1.

    // Block SIGUSR1 to avoid race condition.
    sigset_t sigmask;
    KJ_SYSCALL(sigemptyset(&sigmask));
    KJ_SYSCALL(sigaddset(&sigmask, SIGUSR1));
    KJ_SYSCALL(sigprocmask(SIG_BLOCK, &sigmask, nullptr));

    // Send signal to server monitor to request shell shutdown.
    union sigval sigval;
    memset(&sigval, 0, sizeof(sigval));
    sigval.sival_int = 0;  // indicates stop
    KJ_SYSCALL(sigqueue(serverMonitorPid, SIGINT, sigval));

    // Wait for response.
    int signo;
    KJ_SYSCALL(sigwait(&sigmask, &signo));
    KJ_ASSERT(signo == SIGUSR1);

    auto results = context.getResults();
    results.setShellFds(*shellFds);
    results.setHandle(dropCallback([serverMonitorPid = this->serverMonitorPid]() {
      union sigval sigval;
      memset(&sigval, 0, sizeof(sigval));
      // Send signal to server monitor to request shell startup.
      sigval.sival_int = 1;  // indicates start
      KJ_SYSCALL(sigqueue(serverMonitorPid, SIGINT, sigval));
    }));
    return kj::READY_NOW;
  }
};
