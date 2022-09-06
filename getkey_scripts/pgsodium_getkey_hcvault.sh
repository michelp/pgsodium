#!/bin/bash

HERE=`pwd`
# KV Path in Vault where key is/should be stored.
KEY_PATH=${KEY_PATH:-pgsodium/root}
# Field within KV Path that has the key.
KEY_FIELD=${KEY_FIELD:-key}

KEY=$(vault kv get --field=${KEY_FIELD} "${KEY_PATH}")
if [ $? -ne 0 ]; then
    # Expects the Vault CLI to be installed: https://www.vaultproject.io
    #
    # Expects `VAULT_ADDR` and `VAULT_TOKEN` to be available as
    # environemt variables which will authenticate to Vault.
    KEY=$(vault write -field=random_bytes /sys/tools/random/32 format=hex source=all)
    vault kv put "${KEY_PATH}" ${KEY_FIELD}="${KEY}" 1>&2
fi

echo "${KEY}"
