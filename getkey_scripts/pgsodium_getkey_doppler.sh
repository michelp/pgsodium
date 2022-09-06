#!/bin/bash

HERE=`pwd`
KEY_ID=${KEY_ID:-alias/pgsodium}
ENCRYPTED_ROOT_KEY_FILE=${ENCRYPTED_ROOT_KEY_FILE:-$HERE/pgsodium_encrypted_root.key}

if [ ! -f "$ENCRYPTED_ROOT_KEY_FILE" ]; then
  # Expects the Doppler CLI to be installed: https://docs.doppler.com/docs/install-cli
  #
  # Expects the `DOPPLER_TOKEN` to be available as environment variable which will
  # authenticate the Doppler CLI: https://docs.doppler.com/docs/service-tokens
  doppler secrets get ENCRYPTION_KEY --plain > $ENCRYPTED_ROOT_KEY_FILE
fi

cat $ENCRYPTED_ROOT_KEY_FILE
