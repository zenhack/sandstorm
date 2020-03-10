#include <fcntl.h>
#include <signal.h>
#include <sys/mount.h>
#include <kj/debug.h>
#include <kj/array.h>
#include <kj/io.h>
#include <sandstorm/control-socket.capnp.h>
#include <sandstorm/package.capnp.h>

#include "util.h"
#include "config.h"

namespace sandstorm {

void removeDevPackage(const Config& config, kj::StringPtr pkgId) {
  FdBundle fakeBundle(nullptr);
  mongoCommand(config, fakeBundle, kj::str(
      "db.devpackages.remove({_id:\"", pkgId, "\"})"));
}

class FdImpl final: public FileDescriptor::Server {
public:
  FdImpl(int fd) : fd(fd) {}
  FdImpl(kj::AutoCloseFd&& fd) : fd(kj::mv(fd)) {}

  kj::Maybe<int> getFd() override {
    return fd.get();
  }
private:
  kj::AutoCloseFd fd;
};

class CloseDevShellHandle final: public Handle::Server {
public:
  CloseDevShellHandle(pid_t serverMonitorPid) : serverMonitorPid(serverMonitorPid) {}

  ~CloseDevShellHandle() {
    // Send signal to server monitor to request shell startup.
    union sigval sigval;
    memset(&sigval, 0, sizeof(sigval));
    sigval.sival_int = 1;  // indicates start
    KJ_SYSCALL(sigqueue(serverMonitorPid, SIGINT, sigval));
  }

private:
  pid_t serverMonitorPid;
};

class DevSessionImpl final: public DevSession::Server {
public:
  DevSessionImpl(kj::String&& dir, Config& config)
    : dir(kj::mv(dir)),
      config(config) {
      doUpdateManifest();
    }

  ~DevSessionImpl() {
    rmdir(dir.cStr());
    umount2(dir.cStr(), MNT_FORCE | UMOUNT_NOFOLLOW);
    removeDevPackage(config, pkgId());
  }

  void doUpdateManifest() {
    capnp::ReaderOptions manifestLimits;
    manifestLimits.traversalLimitInWords = spk::Manifest::SIZE_LIMIT_IN_WORDS;

    {
#if 0
      // Read the manifest.
      capnp::StreamFdMessageReader reader(
          raiiOpen(kj::str(dir, "/sandstorm-manifest"), O_RDONLY), manifestLimits);

      // Notify the front-end that the app exists.
      insertDevPackage(config, appId, mountProc, pkgId(), reader.getRoot<spk::Manifest>());
#endif
    }
  }

  kj::Promise<void> updateManifest(UpdateManifestContext context) override {
    doUpdateManifest();
    return kj::READY_NOW;
  }

private:
  const char *pkgId() {
    return strrchr(dir.cStr(), '/') + 1;
  }

  kj::String dir;
  Config& config;
};

class ControllerImpl final: public Controller::Server {
public:
  kj::Promise<void> devShell(DevShellContext context) override {
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

    auto results = context.initResults();
    auto count = shellInherited.size();
    auto shellFds = results.initShellFds(count);
    for(int i = 0; i < count; i++) {
      shellFds.set(i, kj::heap<FdImpl>(shellInherited[i].get()));
    }
    results.setCancel(kj::heap<CloseDevShellHandle>(serverMonitorPid));
    return kj::READY_NOW;
  }

  kj::Promise<void> dev(DevContext context) override {
    KJ_REQUIRE(runningAsRoot, "Sandstorm is not running as root; can't use dev mode.");
    auto appId = context.getParams().getAppId();
    for (char c: appId) {
      KJ_REQUIRE(isalnum(c), "Invalid app ID. Must contain only alphanumerics.");
    }

    char dir[] = "/var/sandstorm/apps/dev-XXXXXX";
    if (mkdtemp(dir) == nullptr) {
      KJ_FAIL_SYSCALL("mkdtemp(dir)", errno, dir);
    }

    DevSession::Client devSession = kj::heap<DevSessionImpl>(kj::str(dir), config);

    KJ_SYSCALL(chown(dir, config.uids.uid, config.uids.gid));

    // We dont use fusermount(1) because it doesn't live in our namespace. For now, this is not
    // a problem because we're root anyway. If in the future we use UID namespaces to avoid being
    // root, then this gets complicated. We could include fusermount(1) in our package, but
    // it would have to be suid-root, defeating the goal of not using root rights.
    auto fuseFd = kj::heap<FdImpl>(raiiOpen("/dev/fuse", O_RDWR));

    auto mountOptions = kj::str("fd=", fuseFd, ",rootmode=40000,"
        "user_id=", config.uids.uid, ",group_id=", config.uids.gid, ",allow_other");

    KJ_SYSCALL(mount("/dev/fuse", dir, "fuse", MS_NOSUID|MS_NODEV, mountOptions.cStr()));

    auto results = context.initResults();
    results.setFuseFd(kj::mv(fuseFd));
    results.setSession(kj::mv(devSession));

    return kj::READY_NOW;
  }

private:
  kj::AutoCloseFd internalFd;
  kj::Array<kj::AutoCloseFd> shellInherited;
  pid_t serverMonitorPid;
  Config config;
  bool runningAsRoot;
};

};
