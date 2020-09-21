#!/bin/bash

HERE=`pwd`
KEY=${KEY:-pgsodium}
KEYRING=${KEYRING:-pgsodium}
LOCATION=${LOCATION:-global}
ROOT_KEY_FILE=${ROOT_KEY_FILE:-$HERE/pgsodium_encrypted_root.key}

if [[ -f "$ROOT_KEY_FILE" ]]; then
    gcloud kms decrypt          \
           --key $KEY           \
           --keyring $KEYRING   \
           --location $LOCATION \
           --plaintext-file -   \
           --ciphertext-file $ROOT_KEY_FILE
else
    >&2 cat <<EOF 
No root key file found at $ROOT_KEY_FILE for pgsodium to load.

See
https://cloud.google.com/kms/docs/creating-keys#kms-create-key-ring-cli
to create a keyring and key.  Then encrypt a secret 32 byte payload
with that key and save it to $ROOT_KEY_FILE.  For example, create a
new keyring and key:

    gcloud kms keyrings create pgsodium --location global
    gcloud kms keys create pgsodium --keyring pgsodium --location global --purpose "encryption"

Then encrypt a strong random key generated with pwgen into $ROOT_KEY_FILE:

    pwgen 64 -s -1 -A -r ghijklmnopqrstuvwxyz | gcloud kms encrypt \\
          --key pgsodium             \\
          --keyring pgsodium         \\
          --location global          \\
          --plaintext-file - --ciphertext-file $ROOT_KEY_FILE

Now restart postgres to initialize pgsodium with the new key.
EOF
    exit 1
fi
