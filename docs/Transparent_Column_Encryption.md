# Transparent Column Encryption

Transparent Column Encryption (TCE) lets you encrypt a column for storage to disk.  This pattern is often called "Encryption at Rest".  The column is stored encrypted in the postgres database files, as well as log streams and database dumps. TCE uses [Server Key Management]() managed keys by ID.  


```python
%load_ext sql
```


```python
%config SqlMagic.feedback=False
%config SqlMagic.displaycon=False
%sql postgresql://postgres@/
```

To use TCE, first create the extension:


```python
%sql CREATE EXTENSION IF NOT EXISTS pgsodium;
```




    []



## Encrypt Whole Column with One Key ID

To encrypt a column, the first step is to create a table.  Here is a simple table with one `text` column that will be encrypted.


```sql
%%sql
DROP TABLE IF EXISTS my_secrets CASCADE;
CREATE TABLE my_secrets (
  secret text
);
```




    []



## Create a new Key ID

The next step is create a single key id that will be used to encrypt the column with the `pgsodium.create_key()` function.  This new key is used to create a label for the column with a `SECURITY LABEL` command that says which key id should be used to encrypt the table.


```python
key = %sql SELECT * FROM pgsodium.create_key()
label = 'ENCRYPT WITH KEY ID ' + str(key[0].id)
print('The security label will be:', label)
```

    The security label will be: ENCRYPT WITH KEY ID 00b27f02-be79-4083-aacd-29d60ad520ab


## Label a column

Now apply that label to the column:


```sql
%%sql 
SECURITY LABEL FOR pgsodium ON COLUMN my_secrets.secret IS :label;
```




    []



You can examine all labeled objects in the standard Postgre catalog table `pg_catalog.pg_seclabel`:


```sql
%%sql 
SELECT objoid::regclass, provider, label FROM pg_seclabel WHERE provider = 'pgsodium';
```




<table>
    <tr>
        <th>objoid</th>
        <th>provider</th>
        <th>label</th>
    </tr>
    <tr>
        <td>pgsodium.key</td>
        <td>pgsodium</td>
        <td>ENCRYPT WITH KEY COLUMN parent_key ASSOCIATED (id, associated_data) NONCE raw_key_nonce</td>
    </tr>
    <tr>
        <td>my_customer_secrets</td>
        <td>pgsodium</td>
        <td>ENCRYPT WITH KEY COLUMN key_id ASSOCIATED (id, associated_data, owner) NONCE nonce</td>
    </tr>
    <tr>
        <td>my_customer_secrets</td>
        <td>pgsodium</td>
        <td>DECRYPT WITH VIEW public.other_name_view</td>
    </tr>
    <tr>
        <td>my_secrets</td>
        <td>pgsodium</td>
        <td>ENCRYPT WITH KEY ID 00b27f02-be79-4083-aacd-29d60ad520ab</td>
    </tr>
</table>



## Insert test data

TCE works by dynamically creating an INSERT trigger for the labled table and a view that wraps the table and decrypts the column.  To explain, here are some test rows for the table.  Note that the inserted secret values are *plaintext*.


```python
%sql INSERT INTO my_secrets (secret) VALUES ('sekert1'), ('shhhhh'), ('0xABC_my_payment_processor_key');
```




    []



## How Secrets are Stored

Now that there are some secrets in the table, selecting on the table will show that the data is stored in an authenticated encrypted form.  The "signature" for authenticated the secret is appended to the value, which is why each value is 32 bytes longer.


```python
%sql SELECT * FROM my_secrets;
```




<table>
    <tr>
        <th>secret</th>
    </tr>
    <tr>
        <td>kU3aImiltQk+UsVBvNFd7NRN3lQutqyQvhzyMmUNtkqC9apvAAKj</td>
    </tr>
    <tr>
        <td>fXDPJean7UQGYiYClQfgXdw0X4bxqgiuDaReddQaI1347oTtKIk=</td>
    </tr>
    <tr>
        <td>/cc70FtpmMz36SzsU7qeaOsGw4kLOE2g1dOIfEbRmanCst8HROWQq6EgssVVUQfi7XndpjQ7c4r5<br>4WrkkEs=</td>
    </tr>
</table>



## Accessing Decrypted Values

When a column is labled with TCE using `SECURITY LABEL`, pgsodium dynamically generate a view that can decrypt rows on the fly.  By default this view is named `decrypted_<table_name>` for the table with any labeled columns.


```python
%sql SELECT * FROM decrypted_my_secrets;
```




<table>
    <tr>
        <th>secret</th>
        <th>decrypted_secret</th>
    </tr>
    <tr>
        <td>kU3aImiltQk+UsVBvNFd7NRN3lQutqyQvhzyMmUNtkqC9apvAAKj</td>
        <td>sekert1</td>
    </tr>
    <tr>
        <td>fXDPJean7UQGYiYClQfgXdw0X4bxqgiuDaReddQaI1347oTtKIk=</td>
        <td>shhhhh</td>
    </tr>
    <tr>
        <td>/cc70FtpmMz36SzsU7qeaOsGw4kLOE2g1dOIfEbRmanCst8HROWQq6EgssVVUQfi7XndpjQ7c4r5<br>4WrkkEs=</td>
        <td>0xABC_my_payment_processor_key</td>
    </tr>
</table>



## Using per-Row Key Ids, Associated Data, and Nonces

The above approach is simple, there is one key to manage and it is used for the whole column.  But in many cases you will want finer grained control over which key is applied to which row.  For example if you host customer content, you may require a different key for different customers.

Furthermore authenticated encryption is useful, but you often have data *associated* with a secret that does not need to be encrypted but does need to be *authenticated* meaning that the associated data is included in the generation of the authentication signature.  See the wikipedia page [Authenticated Encryption with Assocaited Data](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD)) for more information on this technique.  pgsodium lets you specify one or more columns that can be associated with a secret as shown below.

Finally, a common pattern in encryption is to use a *nonce* value to deduplicate secrets and associated data.  Without this nonce, duplicate secrets and associated data would create duplicate encrypted values, and this information can be used by attackers in some situations.

To put it all together, lets create another table for customer secrets:


```sql
%%sql
DROP TABLE IF EXISTS my_customer_secrets CASCADE;
CREATE TABLE my_customer_secrets (
    id bigserial,
    secret text,
    associated_data json,
    owner text NOT NULL,
    key_id uuid REFERENCES pgsodium.key(id) DEFAULT (pgsodium.create_key()).id,
    nonce bytea DEFAULT pgsodium.crypto_aead_det_noncegen());
```




    []




```python
%sql SECURITY LABEL FOR pgsodium ON TABLE my_customer_secrets IS 'DECRYPT WITH VIEW public.other_name_view';
```




    []



Notice that in this case there some new columns, an integer id, an owner, some "associated" data in JSON format, and a nonce. These columns will be used in the security label below.  Notice also that the `key_id` and `nonce` columns have defaults, so that if you don't provide a value for them, a new key_id and nonce will by automatically generated.

The new label has different syntax than the first example, instead of specifying a `KEY ID` the label specifies a `KEY COLUMN` and some optional `ASSOCIATED` data columns, of which there may be one or more, and a `NONCE` column.


```sql
%%sql 
SECURITY LABEL FOR pgsodium ON COLUMN my_customer_secrets.secret 
    IS 'ENCRYPT WITH KEY COLUMN key_id ASSOCIATED (id, associated_data, owner) NONCE nonce';
```




    []



Insert some test data:


```sql
%%sql 
INSERT INTO my_customer_secrets (secret, associated_data, owner) 
    VALUES  ('blue', '{"type":"color"}', 'bob'), 
            ('nuts', '{"type":"food"}',  'alice'),
            ('fast', '{"type":"car"}',   'mallory');
```




    []



As above, secret is now stored en anthenticated encrypted form.  The `id`, `associated_data`, and `owner` columns are "mixed in" to the signature that is stored with the secret, so they cannot be forged.  Any atttempt to decrypt the secret with inauthentic associated data will fail.


```python
%sql SELECT secret, associated_data, owner, key_id FROM my_customer_secrets;
```




<table>
    <tr>
        <th>secret</th>
        <th>associated_data</th>
        <th>owner</th>
        <th>key_id</th>
    </tr>
    <tr>
        <td>wXmJsarHnYeDFS5bfkipBJny8/3CwM6YIxVbonkIoES/Oeqe</td>
        <td>{&#x27;type&#x27;: &#x27;color&#x27;}</td>
        <td>bob</td>
        <td>bb4c5512-2eed-4254-a262-b3a53b16e795</td>
    </tr>
    <tr>
        <td>d9hUv3oA2n0HtydyWLae1IAtcYP/nOH2i8tm1xTMlKLECMSk</td>
        <td>{&#x27;type&#x27;: &#x27;food&#x27;}</td>
        <td>alice</td>
        <td>1a7b37b1-f8a2-4a83-b410-da115c51a1db</td>
    </tr>
    <tr>
        <td>/nJpnMbrh7me5KwwLWHC0+rvLV8J6SEDI3LNsM5qmZN6VNgF</td>
        <td>{&#x27;type&#x27;: &#x27;car&#x27;}</td>
        <td>mallory</td>
        <td>e580cf08-3d15-4425-8520-91ea66142a22</td>
    </tr>
</table>



Decrypted secret access the view by the name specified in the table label above.


```python
%sql SELECT decrypted_secret, associated_data, owner, key_id FROM other_name_view;
```




<table>
    <tr>
        <th>decrypted_secret</th>
        <th>associated_data</th>
        <th>owner</th>
        <th>key_id</th>
    </tr>
    <tr>
        <td>blue</td>
        <td>{&#x27;type&#x27;: &#x27;color&#x27;}</td>
        <td>bob</td>
        <td>bb4c5512-2eed-4254-a262-b3a53b16e795</td>
    </tr>
    <tr>
        <td>nuts</td>
        <td>{&#x27;type&#x27;: &#x27;food&#x27;}</td>
        <td>alice</td>
        <td>1a7b37b1-f8a2-4a83-b410-da115c51a1db</td>
    </tr>
    <tr>
        <td>fast</td>
        <td>{&#x27;type&#x27;: &#x27;car&#x27;}</td>
        <td>mallory</td>
        <td>e580cf08-3d15-4425-8520-91ea66142a22</td>
    </tr>
</table>


