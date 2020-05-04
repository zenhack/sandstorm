This directory exists because typescript *really* doesn't like
"dynamic" imports like node-capnp's `Capnp.importSystem`.
Instead, for each schema we need to import from typescript, we
write a simple shim module in this directory that allows us to use
normal es6 imports in our typescript code. See the files in this
directory for examples.
