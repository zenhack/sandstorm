#!/bin/bash

# Runs `meteor test`. The tests run on a fresh isolated Mongo instance.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

run_build() {
  (cd "$SCRIPT_DIR/.." && make shell-env)
  cd "$SCRIPT_DIR"
}

SKIP_BUILD="no"
handle_args() {
  while getopts "f" opt; do
    case $opt in
      f)
        SKIP_BUILD="yes"
        ;;
      *)
        echo "You can add '-f' to skip the build step"
        exit 1
        ;;
    esac
  done
}
handle_args "$@"

if [ "yes" != "$SKIP_BUILD" ]; then
  run_build
fi

SETTINGS=$(mktemp)

cat > $SETTINGS << __EOF__
{
  "public": {
    "buildstamp": "[local dev front-end]",
    "allowDemoAccounts": true,
    "allowDevAccounts": true,
    "allowUninvited": ${ALLOW_UNINVITED:-false},
    "isTesting": true,
    "wildcardHost": "*.local.sandstorm.io"
  }
}
__EOF__

# Work-around for problem where Meteor's bundled npm prefers the system gyp
# over its own bundled version, and the system gyp doesn't work.
export PYTHONPATH=$("$SCRIPT_DIR/../find-meteor-dev-bundle.sh")/lib/node_modules/npm/node_modules/node-gyp/gyp/pylib

# Terrible hack: Make capnp.node available to tests.
rm -f /tmp/node_modules
ln -s "$(dirname "$PWD")/node_modules" /tmp/node_modules

meteor test \
  --once \
  --driver-package=meteortesting:mocha \
  --settings "$SETTINGS"
