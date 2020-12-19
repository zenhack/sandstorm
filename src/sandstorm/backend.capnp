# Sandstorm - Personal Cloud Sandbox
# Copyright (c) 2015 Sandstorm Development Group, Inc. and contributors
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

@0xdcbc0d702b1b47a5;

$import "/capnp/c++.capnp".namespace("sandstorm");

using Json = import "/capnp/compat/json.capnp";

using Util = import "util.capnp";
using Package = import "package.capnp";
using Supervisor = import "supervisor.capnp".Supervisor;
using SandstormCore = import "supervisor.capnp".SandstormCore;
using GrainInfo = import "grain.capnp".GrainInfo;

using WebSession = import "web-session.capnp".WebSession;
using ApiSession = import "api-session.capnp".ApiSession;

interface Backend {
  # Interface that thet Sandstorm front-end uses to talk to the "back end", i.e. the container
  # scheduler.

  ping @14 ();
  # Just returns. Used to verify that the connection to the back-end is alive and well.

  # ----------------------------------------------------------------------------

  startGrain @0 (ownerId :Text, grainId :Text, packageId :Text,
                 command :Package.Manifest.Command, isNew :Bool,
                 devMode :Bool = false, mountProc :Bool = false)
             -> (supervisor :Supervisor);
  # Start a grain.

  getGrain @1 (ownerId :Text, grainId :Text) -> (supervisor :Supervisor);
  # Get the grain if it's running, or throw a DISCONNECTED exception otherwise.

  deleteGrain @2 (ownerId :Text, grainId :Text);
  # Delete a grain from disk. Succeeds silently if the grain doesn't exist.

  transferGrain @12 (ownerId :Text, grainId :Text, newOwnerId :Text);
  # Transfer a grain's ownership.

  deleteUser @13 (userId :Text);
  # Delete an entire user. May or may not delete grains.

  # ----------------------------------------------------------------------------

  installPackage @3 () -> (stream :PackageUploadStream);
  interface PackageUploadStream extends(Util.ByteStream) {
    saveAs @0 (packageId :Text) -> (appId :Text, manifest :Package.Manifest,
                                    authorPgpKeyFingerprint :Text);
    # `authorPgpKeyFingerprint` is present only if the signature is valid, and is null if there
    # is no signature. (Invalid signature throws exception.)
  }

  tryGetPackage @4 (packageId :Text) -> (appId :Text, manifest :Package.Manifest,
                                         authorPgpKeyFingerprint :Text);
  # Get info from an already-installed package. Return values are null if the package doesn't
  # exist.

  deletePackage @5 (packageId :Text);
  # Delete a package from disk. Succeeds silently if the package doesn't exist.

  # ----------------------------------------------------------------------------
  # backups

  backupGrain @6 (backupId :Text, ownerId :Text, grainId :Text, info :GrainInfo);
  # Makes a .zip of the contents of the given grain and stores it as a backup file.

  restoreGrain @7 (backupId :Text, ownerId :Text, grainId :Text) -> (info :GrainInfo);
  # Unpack a stored backup into a new grain.

  uploadBackup @8 (backupId :Text) -> (stream :Util.ByteStream);
  # Upload a zip to create a new backup. If `stream.done()` does not get called and return
  # successfully, the backup wasn't saved.

  downloadBackup @9 (backupId :Text, stream :Util.ByteStream);
  # Download a stored backup, writing it to `stream`.

  deleteBackup @10 (backupId :Text);
  # Delete a stored backup from disk. Succeeds silently if the backup doesn't exist.

  # ----------------------------------------------------------------------------

  getUserStorageUsage @11 (userId :Text) -> (size :UInt64);
  # Returns the number of bytes of data in storage attributed to the given user.
  #
  # This method is not implemented by the single-machine version of Sandstorm, which does not track
  # per-user storage quotas.

  getGrainStorageUsage @15 (ownerId :Text, grainId :Text) -> (size :UInt64);
  # Returns the number of bytes of data in storage attributed to the given grain.
  #
  # On single-machine Sandstorm, this walks the directory tree, which may be slow. Therefore,
  # it is recommended that this not be called often.
}

interface GatewayRouter {
  # Interface which the gateway (C++ code which directly handles HTTP and other traffic) uses to
  # call into Sandstorm's business logic (Node.js process) in order to figure out how to route
  # things.
  #
  # (The Gateway actually conencts to the backend first, which gives it a GatewayRouter as the
  # bootstrap capability. The backend hooks that capability up to the shell, making sure to update
  # the routing any time the shell dies and restarts.)
  #
  # Note that the gateway also makes direct HTTP/WebSocket and SMTP connections for traffic that
  # it does not know how to handle directly.

  openUiSession @0 (sessionCookie :Text, params :WebSession.Params)
                -> (session :WebSession, loadingIndicator :Util.Handle, parentOrigin :Text,
                    csp :ContentSecurityPolicy);
  # Given a sandstorm-sid cookie value for a UI session, find the WebSession to handle requests.
  #
  # The gateway may cache the session capability, associated with this cookie value, for as long
  # as it wants. However, session will become disconnected if the grain shuts down or if the user's
  # privileges are revoked. In that case, the gateway will need to discard the capability and
  # request a new one.
  #
  # While `loadingIndicator` is held, the user will see a loading indicator on their screen. Drop
  # this capability when the first HTTP response is received from the app to make the loading
  # indicator go away.
  #
  # `parentOrigin` is the origin permitted to frame this UI session. E.g. Content-Security-Policy
  # frame-ancestors should be used to block clickjacking.
  #
  # `csp` should be used to determine the Content-Security-Policy for this session, and
  # to report violations.

  struct ContentSecurityPolicy {
    # A content security policy for a ui session.

    currentPolicy @0 :Util.Assignable(Policy).Getter;
    # Getter for the policy itself. The gateway should subscribe to this to receive
    # updates.

    reporter @1 :Reporter;
    # Use this to report violations of the policy.

    struct Policy {
      # The policy to impose on this session.
      #
      # If the config option ALLOW_LEGACY_RELAXED_CSP is set to true, then
      # this is ignored entirely and a lax policy is used.
      #
      # Otherwise, the default policy blocks loading of all third-party
      # resources.

      allowMedia @0 :Bool;
      # If true, allow loading images & media from third party origins.
    }

    interface Reporter {
      reportViolation @0 (report :ViolationReport);
    }

    struct ViolationReport {
      # Content of a CSP violation report, as described in:
      #
      # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only#Violation_report_syntax
      #
      # We only include the fields here that we currently actually use.
      cspReport :group $Json.name("csp-report") {
        disposition @0 :Disposition;
        violatedDirective @1 :Text $Json.name("violated-directive");
      }
      enum Disposition {
        enforce @0;
        report @1;
      }
    }
  }

  interface CspHandler {
    # A `CspHandler` is used to manage Content-Security-Policy for a ui session. Sandstorm
    # takes the following approach to apps loading third-party images and media:
    #
    # - By default, block these using CSP
    # - Set the CSP report-uri and report-to fields to a distinct value for each
    #   session.
    # - If a CSP violation report for media is received, display a popup in the Sandstorm
    #   UI telling the user that media has been blocked for privacy reasons, and give them
    #   the option to allow access.
    # - If the user opts to allow access, change the CSP policy and refresh the page.
    #
    # The `CspHandler` is used by the gateway to inform the shell of such reports.


    struct SessionPolicy {
      # Specification of a Content Security Policy to use for a given session.

      allowMedia @0 :Bool;
      # Should media (images/video) be allowed?
    }

    reportViolation @0 (usedPolicy :SessionPolicy);
    # Report that a CSP violation was received. The argument is the policy that
    # had been set.

    sessionPolicy @1 (getter :Util.Assignable(SessionPolicy).Getter);
    # Get the current session policy for this session. The gateway should subscribe
    # to this to get notifications of policy changes.
  }

  openApiSession @1 (apiToken :Text, params :ApiSession.Params) -> (session :ApiSession);
  # Given a token from an `Authorization` header, find the ApiSession to handle requests.
  #
  # The gateway may cache the session capability, associated with this token, for as long as it
  # wants. However,  session will become disconnected if the grain shuts down or if the user's
  # privileges are revoked. In that case, the gateway will need to discard the capability and
  # request a new one.
  #
  # Generally, traffic on an ApiSession will force the grain to stay running. This differs from UI
  # sessions, where the Sandstorm shell keeps track of which grains are open in tabs and decides
  # whether their servers need to keep running.

  keepaliveApiToken @8 (apiToken :Text, durationMs :UInt32);
  # Bumps the timer on a self-destructing API token.

  getApiHostResource @7 (hostId :Text, path :Text)
      -> (resource :StaticResource);
  # Get info to respond to a  GET request on an API host, without need for a token. If `resource`
  # is null, then a 401 should be returned instead to induce authentication.

  struct StaticResource {
    type @0 :Text;
    language @1 :Text;
    encoding @2 :Text;
    body @3 :Data;
  }

  getApiHostOptions @6 (hostId :Text) -> (dav :List(Text));
  # Get info to respond to an OPTIONS request on an API host, without need for a token.

  getStaticAsset @2 (id :Text) -> (content :Data, type :Text, encoding :Text);
  # Look up the content of a static asset by ID. `type` and `encoding` are the values for the
  # `Content-Type` and `Content-Encoding` headers, respectively.

  getStaticPublishingHost @3 (publicId :Text) -> (supervisor :Supervisor);
  # Maps a grain's "public ID" to a grain supervisor, whose getWwwFileHack() method will be used
  # to host static files.

  routeForeignHostname @4 (hostname :Text) -> (info :ForeignHostnameInfo);
  # Called when the gateway receives a request for a hostname that doesn't match any of the
  # expected hostname patterns, to figure out what it is.

  struct ForeignHostnameInfo {
    union {
      unknown @0 :Void;
      # This is not a known host.

      staticPublishing @1 :Text;
      # It's a static publishing host. Value is the public ID.

      standalone @2 :Void;
      # It's a standalone host. HTTP requests should be routed directly to Node business logic.
    }

    ttlSeconds @3 :UInt32;
    # How long the receiver can safely cache this lookup result.
  }

  subscribeTlsKeys @5 (callback :TlsKeyCallback);
  # Retrieves the current TLS key and certificate and subscribes to future changes to these.
  #
  # This method does not return unless disconnected.

  interface TlsKeyCallback {
    setKeys @0 (key :Text, certChain :Text);
    # Sets the current TLS key and certificate, which will be used for all incoming connections
    # until setKeys() is called again.
    #
    # If `key` and `certChain` are null, the shell is informing the gateway that no TLS keys are
    # configured at all.
    #
    # If PRIVATE_KEY_PASSWORD is set in sandstorm.conf, then `key` is expected to be encrypted with
    # that password. This provides a little bit of additional security in that the password is
    # never revealed to the shell process nor to Mongo.
  }

  # TODO(someday): We could possibly eliminate the need for any HTTP traffic to Node by serving
  #   static assets directly from the gateway and by opening the DDP WebSocket over Cap'n Proto.
  #   However, this might not be a win until Cap'n Proto is implemented in native Javascript on the
  #   Node side.
}

interface ShellCli {
  createAcmeAccount @0 (directory :Text, email :Text, agreeToTerms :Bool);
  setAcmeChallenge @1 (module :Text, options :Text);
  renewCertificateNow @2 ();
}

interface SandstormCoreFactory {
  # Interface that the Sandstorm front-end exports to the backend in order to expose business
  # logic hooks.
  #
  # TODO(cleanup): Rename to something more appropriate, now that this does more than construct
  #   SansdtormCores.

  getSandstormCore @0 (grainId :Text) -> (core :SandstormCore);
  # Create a SandstormCore for a grain. Eventually, we'll move away from implementing SandstormCore
  # in the front-end and have it be implemented in the backend. This method will go away then.

  getGatewayRouter @1 () -> (router :GatewayRouter);
  # Gets an GatewayRouter implementation. Note that in Blackrock, where multiple instances of the
  # shell might be running, all GatewayRouters are equivalent, regardless of which shell replica
  # they came from.

  getShellCli @2 () -> (shellCli :ShellCli);
  # Gets a ShellCli implementation, which is used by the CLI to issue commands directly to the
  # shell.
}
