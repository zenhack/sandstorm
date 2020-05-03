@0xd2d5e4f0f4e9ffd6;

$import "/capnp/c++.capnp".namespace("sandstorm");

using Util = import "util.capnp";
using WebSession = import "web-session.capnp".WebSession;

interface PublicWebView {
  # View of a "public" website.

  newWebSession @0 (params :WebSession.Params) -> (session :WebSession);
  # Create a new web session.
}
