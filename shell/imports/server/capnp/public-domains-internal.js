import Capnp from "/imports/server/capnp.js";
const PublicDomainsInternal = Capnp.importSystem("sandstorm/public-domains-internal.capnp");
export const PublicWebViewSetter = PublicDomainsInternal.PublicWebViewSetter;
export default PublicDomainsInternal;
