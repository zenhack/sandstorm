#include <sys/random.h>
#include <kj/debug.h>
#include <kj/encoding.h>
#include <capnp/serialize.h>

#include "csp-manager.h"

namespace sandstorm {
CspManager::CspManager(
  GatewayRouter::ContentSecurityPolicy::Reporter::Client reporter,
  bool allowLegacyRelaxed)
  : reporter(reporter),
    allowLegacyRelaxed(allowLegacyRelaxed),
    policy(makeDefaultPolicy()),
    reportKey(makeReportKey())
  {}

kj::String CspManager::makeReportKey() {
  uint8_t bytes[16];
  kj::ArrayPtr<uint8_t> array(&bytes[0], 16);
  KJ_SYSCALL(getrandom(array.begin(), array.size(), 0));
  return kj::encodeBase64Url(array);
}

kj::Own<GatewayRouter::ContentSecurityPolicy::Policy::Reader> CspManager::makeDefaultPolicy() {
  auto msg = kj::heap<capnp::MallocMessageBuilder>();
  auto policy = msg->initRoot<GatewayRouter::ContentSecurityPolicy::Policy>();
  return capnp::clone(policy.asReader());
}

bool CspManager::isLegacyRelaxed() {
  return allowLegacyRelaxed;
}

kj::Promise<void> CspManager::set(SetContext context) {
  policy = capnp::clone(context.getParams().getValue());
  return kj::READY_NOW;
}

kj::StringPtr CspManager::getReportKey() {
  return reportKey;
}

GatewayRouter::ContentSecurityPolicy::Reporter::Client& CspManager::getReporter() {
  return reporter;
}

GatewayRouter::ContentSecurityPolicy::Policy::Reader& CspManager::currentPolicy() {
  return *policy;
}


}
