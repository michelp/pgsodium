# Key Exchange

Using the key exchange API, two parties can securely compute a set of shared keys using their peer's public key and their own secret key.


```python
%load_ext sql
```


```python
%config SqlMagic.feedback=False
%config SqlMagic.displaycon=False
%sql postgresql://postgres@/
```


```sql
%%sql 
CREATE EXTENSION IF NOT EXISTS pgsodium;
```




    []



### `crypto_kx_new_keypair()`


```python
bob = %sql select public, secret from pgsodium.crypto_kx_new_keypair()
bob_public, bob_secret = bob[0][0].tobytes(), bob[0][1].tobytes()

alice = %sql select public, secret from pgsodium.crypto_kx_new_keypair()
alice_public, alice_secret = alice[0][0].tobytes(), alice[0][1].tobytes()
```

### `crypto_kx_client_session_keys(client_public bytea, client_secret bytea, server_public bytea)`


```python
bob_keys = %sql select tx, rx from pgsodium.crypto_kx_client_session_keys(:bob_public, :bob_secret, :alice_public)
```

### `crypto_kx_server_session_keys(server_public bytea, server_secret bytea, client_public bytea)`


```python
alice_keys = %sql select tx, rx from pgsodium.crypto_kx_server_session_keys(:alice_public, :alice_secret, :bob_public)
```
