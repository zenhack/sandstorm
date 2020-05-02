#ifndef SANDSTORM_CONTROL_SOCKET_H_
#define SANDSTORM_CONTROL_SOCKET_H_

#include <kj/io.h>
#include <sandstorm/control-socket.capnp.h>

namespace sandstorm {
  FileDescriptor::Client exportFd(kj::AutoCloseFd&& fd);

  class ControllerImpl final: public Controller::Server {
    public:
      ControllerImpl(
          pid_t serverMonitorPid,
          kj::Own<ShellFDs::Reader>&& shellFds);

      kj::Promise<void> devShell(DevShellContext context) override;
    private:
      pid_t serverMonitorPid;
      kj::Own<ShellFDs::Reader> shellFds;
  };
};

#endif
