#pragma once

#include <sandstorm/util.capnp.h>
#include <sandstorm/backend.capnp.h>

namespace sandstorm {

class CspManager final
    : public kj::Refcounted,
      public Assignable<GatewayRouter::ContentSecurityPolicy::Policy>::Setter::Server {
  public:
    KJ_DISALLOW_COPY(CspManager);

    CspManager(
      GatewayRouter::ContentSecurityPolicy::Reporter::Client reporter,
      bool allowLegacyRelaxed
    );

    bool isLegacyRelaxed();

    kj::StringPtr getReportKey();

    GatewayRouter::ContentSecurityPolicy::Reporter::Client& getReporter();
    GatewayRouter::ContentSecurityPolicy::Policy::Reader& currentPolicy();

    kj::Promise<void> set(SetContext context) override;

  private:
    GatewayRouter::ContentSecurityPolicy::Reporter::Client reporter;
    bool allowLegacyRelaxed;
    kj::Own<GatewayRouter::ContentSecurityPolicy::Policy::Reader> policy;

    kj::String reportKey;

    static kj::Own<GatewayRouter::ContentSecurityPolicy::Policy::Reader> makeDefaultPolicy();
    static kj::String makeReportKey();
};

};
