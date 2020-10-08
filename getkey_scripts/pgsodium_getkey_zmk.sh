#!/bin/bash

HERE=`pwd`
KEY=${KEY:-pgsodium}
ROOT_KEY_FILE=${ROOT_KEY_FILE:-$HERE/pgsodium_encrypted_root.key}

if [[ -f "$ROOT_KEY_FILE" ]]; then
	python3 <<EOF
from zymkey import Zymkey
z = Zymkey()
with open('$ROOT_KEY_FILE', 'rb') as f:
	 z.unlock(f.read()).hex()
EOF
	
else
    >&2 cat <<EEOF
No root key file found at $ROOT_KEY_FILE for pgsodium to load.

Using the zymkey API, encrypt (lock) a secret 32 byte payload and save
it to $ROOT_KEY_FILE.  For example:

pwgen 64 -s -1 -A -r ghijklmnopqrstuvwxyz | python3 <<EOF
import zymkey, sys
z = zymkey.Zymkey()
with open('$ROOT_KEY_FILE', 'wb') as f:
     f.write(z.lock(bytes.fromhex(sys.stdin.read())))
EOF

Now restart postgres to initialize pgsodium with the new key.
EEOF
    exit 1
fi
