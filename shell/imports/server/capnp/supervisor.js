import Capnp from "/imports/server/capnp.js";

const Supervisor = Capnp.importSystem("sandstorm/supervisor.capnp");
export const SystemPersistent = Supervisor.SystemPersistent;
export default Supervisor;
