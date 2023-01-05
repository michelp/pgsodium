# pgsodium User Guide

pgsodium is an encryption library extension for
[PostgreSQL](https://www.postgresql.org/) using the
[libsodium](https://download.libsodium.org/doc/) library for high
level cryptographic algorithms.

pgsodium can be used a straight interface to libsodium, but it can
also use a powerful feature called [Server Key
Management](./Server_Key_Management.md) where pgsodium loads an external
secret key into memory that is never accessible to SQL.  This
inaccessible root key can then be used to derive sub-keys that are used
for encryption and decryption instead of the raw keys themselves.


- [Configuration](Configuration.md)
- [Generating Random Data](Generating_Random_Data.md)
- [Hashing](Hashing.md)
- [Password Hashing](Password_Hashing.md)
- [Hash-Based Message Authentication Codes (HMAC)](HMAC.md)
- [Secret Key Cryptography](Secret_Key_Cryptography.md)
- [Public Key Cryptography](Public_Key_Cryptography.md)
- [Authenticated Encryption With Additional Data (AEAD)](Authenticated_Encryption_With_Additional_Data.md)
- [Key Derivation](Key_Derivation.md)
- [Key Exchange](Key_Exchange.md)
- [Signcryption](Signcryption.md)

