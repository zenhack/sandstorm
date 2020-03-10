#ifndef SANDSTORM_MONGO_H_
#define SANDSTORM_MONGO_H_

void mongoCommand(const Config& config, FdBundle& fdBundle,
                  kj::StringPtr command, kj::StringPtr db = "meteor");

[[noreturn]] void execMongoClient(const Config& config,
      std::initializer_list<kj::StringPtr> optionArgs,
      std::initializer_list<kj::StringPtr> fileArgs,
      kj::StringPtr dbName = "meteor");

#endif
