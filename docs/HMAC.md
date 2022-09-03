## Hash-based Message Authentication Codes

[https://en.wikipedia.org/wiki/HMAC]

In cryptography, an HMAC (sometimes expanded as either keyed-hash
message authentication code or hash-based message authentication code)
is a specific type of message authentication code (MAC) involving a
cryptographic hash function and a secret cryptographic key. As with
any MAC, it may be used to simultaneously verify both the data
integrity and authenticity of a message.

    select crypto_auth_hmacsha512_keygen() hmac512key \gset
    select crypto_auth_hmacsha512('food', :'hmac512key') hmac512 \gset

    select is(crypto_auth_hmacsha512_verify(:'hmac512', 'food', :'hmac512key'), true, 'hmac512 verified');
    select is(crypto_auth_hmacsha512_verify(:'hmac512', 'fo0d', :'hmac512key'), false, 'hmac512 not verified');

[C API Documentation](https://doc.libsodium.org/advanced/hmac-sha2)

