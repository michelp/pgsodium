# Server Key Management


```python
%load_ext sql
```


```python
%config SqlMagic.feedback=False
%config SqlMagic.displaycon=False
%sql postgresql://postgres@/
```

The core feature of pgsodium its its ability to manage encryption keys for you, you so that you never reference a raw encryption key, but instead you reference keys *by ID*.  A key id is a UUID that uniquely identifies the key used.  An example of using Server Key Management can be found in the section on [Transparent Column Encryption](Transparent_Column_Encryption.md) and is most of the API examples that can take key UUIDs are arguments.

## The hidden root key

 

## Create a new Key

pgsodium can manage two types of keys, *derived* keys, and *external* keys.  Derived keys use libsodium to 

Server managed keys are created with the `pgsodium.create_key()` function.  This function takes a few optional parameters:
- `key_type`: The type of key to create, the default is `aead-det`.  Can be one of:
  - `aead-det`
  - `aead-ietf`
  - `hmacsha512`
  - `hmacsha256`
  - `auth`
  - `secretbox`
  - `secretstream`
  - `shorthash`
  - `generichash`
  - `kdf`
- `name`: An optional *unique* name for the key.  The default is NULL which makes an "anonymous" key.
- `derived_key`: An optional raw external key, for example an hmac key from an external service.  pgsodium will store this key encrypted with TCE.
- `derived_key_nonce`: An optional nonce for the raw key, if none is provided a new random `aead-det` nonce will be generated using `pgsodium.crypto_aead_det_noncegen()`.
- `parent_key`: If `raw_key` is not null, then this key id is used to encrypt the raw key.  The default is to generate a new `aead-det` key.
- `derived_context`
- `expires`
- `associated_data`

`pgsodium.create_key()` returns a new row in the `pgsodium.valid_key` view.  For most purposes, you usually just need the new key's ID to start using it.  For example, here's a new external shahmac256 key being created and used to verify a payload:


```python
external_key = %sql select pgsodium.crypto_auth_hmacsha256_keygen()
external_key = bytes(external_key[0][0])
print(external_key)
```

    b'\x1d\xa5\xf2\xa0a\xa8\x03 \x9b\x88J\xfe\xd2Xc\x0cG\xc5{\xc3W\xd7\x91KXp\x87\x15\x02"\xd6\xf6'



```python
%sql select * from pgsodium.create_key('hmacsha256', raw_key:=:external_key)
```




<table>
    <tr>
        <th>id</th>
        <th>name</th>
        <th>status</th>
        <th>key_type</th>
        <th>key_id</th>
        <th>key_context</th>
        <th>created</th>
        <th>expires</th>
        <th>associated_data</th>
    </tr>
    <tr>
        <td>92e24493-2df6-422b-8c75-00c82b1097c4</td>
        <td>None</td>
        <td>valid</td>
        <td>hmacsha256</td>
        <td>None</td>
        <td>None</td>
        <td>2022-09-05 19:46:07.340760+00:00</td>
        <td>None</td>
        <td></td>
    </tr>
</table>




```python
%sql select id, key_type, parent_key, length(decrypted_raw_key) from pgsodium.decrypted_key where key_type = 'hmacsha256';
```




<table>
    <tr>
        <th>id</th>
        <th>key_type</th>
        <th>parent_key</th>
        <th>length</th>
    </tr>
    <tr>
        <td>5a8720af-50aa-4bd9-a9f1-c71065e75a88</td>
        <td>hmacsha256</td>
        <td>451843b3-74f8-4458-bc2d-5a88c6024832</td>
        <td>32</td>
    </tr>
    <tr>
        <td>9fac7ff7-10d7-4139-966b-f7317e4486b2</td>
        <td>hmacsha256</td>
        <td>a1f91b67-2793-4788-ab8e-4fca32e360da</td>
        <td>32</td>
    </tr>
    <tr>
        <td>92e24493-2df6-422b-8c75-00c82b1097c4</td>
        <td>hmacsha256</td>
        <td>cc815230-06c6-4d57-9780-ac2a2dc026bc</td>
        <td>32</td>
    </tr>
</table>


