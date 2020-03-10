#include <kj/string.h>

#include "config.h"

namespace sandstorm {

void mongoCommand(const Config& config, FdBundle& fdBundle,
                  kj::StringPtr command, kj::StringPtr db = "meteor") {
  char commandFile[] = "/tmp/mongo-command.XXXXXX";
  int commandRawFd;
  KJ_SYSCALL(commandRawFd = mkstemp(commandFile));
  kj::AutoCloseFd commandFd(commandRawFd);
  KJ_DEFER(unlink(commandFile));
  if (runningAsRoot) {
    KJ_SYSCALL(fchown(commandRawFd, -1, config.uids.gid));
    KJ_SYSCALL(fchmod(commandRawFd, 0660));
  }
  kj::FdOutputStream(kj::mv(commandFd)).write(command.begin(), command.size());

  Subprocess process([&]() -> int {
    fdBundle.closeAll();

    // Don't run as root.
    dropPrivs(config.uids);

    execMongoClient(config, {"--quiet"}, {commandFile}, db);
    KJ_UNREACHABLE;
  });
  process.waitForSuccess();
}

[[noreturn]] void execMongoClient(const Config& config,
      std::initializer_list<kj::StringPtr> optionArgs,
      std::initializer_list<kj::StringPtr> fileArgs,
      kj::StringPtr dbName = "meteor") {
  auto db = kj::str("127.0.0.1:", config.mongoPort, "/", dbName);

  kj::Vector<const char*> args;
  args.add("/bin/mongo");

  // If /var/mongo/passwd exists, we interpret it as containing the password for a Mongo user
  // "sandstorm", and assume we are expected to log in as this user.
  kj::String passwordArg;
  if (access("/var/mongo/passwd", F_OK) == 0) {
    passwordArg = kj::str("--password=", trim(readAll(raiiOpen("/var/mongo/passwd", O_RDONLY))));

    args.add("-u");
    args.add("sandstorm");
    args.add(passwordArg.cStr());
    args.add("--authenticationDatabase");
    args.add("admin");
  }

  for (auto& arg: optionArgs) {
    args.add(arg.cStr());
  }

  args.add(db.cStr());

  for (auto& arg: fileArgs) {
    args.add(arg.cStr());
  }

  args.add(nullptr);

  // OK, run the Mongo client!
  KJ_SYSCALL(execv(args[0], const_cast<char**>(args.begin())));
  KJ_UNREACHABLE;
}
};
