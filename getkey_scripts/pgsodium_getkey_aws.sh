#!/bin/bash

HERE=`pwd`
KEY_ID=${KEY_ID:-alias/pgsodium}
ENCRYPTED_ROOT_KEY_FILE=${ENCRYPTED_ROOT_KEY_FILE:-$HERE/pgsodium_encrypted_root.key}

if [[ -f "$ENCRYPTED_ROOT_KEY_FILE" ]]; then
	aws kms decrypt --ciphertext-blob fileb://$ENCRYPTED_ROOT_KEY_FILE --query Plaintext --output text | base64 --decode | hex
else
	aws kms generate-data-key --number-of-bytes=32 --key-id=$KEY_ID --query CiphertextBlob --output text | base64 --decode > $ENCRYPTED_ROOT_KEY_FILE
	aws kms decrypt --ciphertext-blob fileb://$ENCRYPTED_ROOT_KEY_FILE --query Plaintext --output text | base64 --decode | hex
fi

