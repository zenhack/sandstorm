#ifndef SANDSTORM_SECCOMP_H_
#define SANDSTORM_SECCOMP_H_

namespace sandstorm {

void setupSeccompLegacy(bool devmode, bool dumpPfc);

void setupSeccompNew();

};

#endif
