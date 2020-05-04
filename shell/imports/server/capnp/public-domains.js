import Capnp from "/imports/server/capnp.js";
const PublicDomains = Capnp.importSystem("sandstorm/public-domains.capnp");
export const PublicWebView = PublicDomains.PublicWebView;
export default PublicDomains;
