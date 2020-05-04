@0xc5ff257c08e72f8f;


$import "/capnp/c++.capnp".namespace("sandstorm");

using Assignable = import "util.capnp".Assignable;
using PublicWebView = import "public-domain.capnp".PublicWebView;

interface PublicWebViewSetter extends(Assignable(PublicWebView).Setter) {}
