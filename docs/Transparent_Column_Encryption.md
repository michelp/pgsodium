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
CREATE TABLE IF NOT EXISTS my_secrets (
  secret text
);
TRUNCATE my_secrets;  -- so the notebook is repeatable with a new key each time
```




    []



## Create a new Key ID

The next step is create a single key id that will be used to encrypt the column with the `pgsodium.create_key()` function.  This new key is used to create a label for the column with a `SECURITY LABEL` command that says which key id should be used to encrypt the table.


```python
key = %sql SELECT * FROM pgsodium.create_key();
key = key[0][0]
label = 'ENCRYPT WITH KEY ID ' + str(key)
print('The security label will be:', label)
```

    The security label will be: ENCRYPT WITH KEY ID 1cfaecf3-c2dc-483a-96c9-8eb98e8743a5


## Label a column

Now apply that label to the column:


```sql
%%sql 
SECURITY LABEL FOR pgsodium ON COLUMN my_secrets.secret IS :label;
```




    []



## Insert test data

Here are some test rows for the table.  Note that the inserted secret values are *plaintext*.


```sql
%%sql
INSERT INTO my_secrets (secret) VALUES ('sekert1'), ('1234567'), ('9999');
```




    []



## How Secrets are Stored

Now that there are some secrets in the table, selecting on the table will show that the data is stored in an authenticated encrypted form.  The "signature" for authenticated the secret is appended to the value, which is why each value is 32 bytes longer.


```sql
%%sql
SELECT * FROM my_secrets;
```




<table>
    <tr>
        <th>secret</th>
    </tr>
    <tr>
        <td>27KzhM6v2qg6UjCHXDfdXirDEKTbpXEUsGnEvgkSPfsc5PnDiwau</td>
    </tr>
    <tr>
        <td>/10jpUIdj54uLgvBL0cSlCNmXdV5I5HvvsPLD2Hbin7cdxvWg1Mc</td>
    </tr>
    <tr>
        <td>C1hQcfwVa/mIYf0udv/tMegOoPuBdkKqb0/K9USLgutJ1Whg</td>
    </tr>
</table>



## Accessing Decrypted Values

When a column is labled with TCE using `SECURITY LABEL`, pgsodium dynamically generate a view that can decrypt rows on the fly.  By default this view is named `decrypted_<table_name>` for the table with any labeled columns.


```sql
%%sql
SELECT * FROM decrypted_my_secrets;
```




<table>
    <tr>
        <th>secret</th>
        <th>decrypted_secret</th>
    </tr>
    <tr>
        <td>27KzhM6v2qg6UjCHXDfdXirDEKTbpXEUsGnEvgkSPfsc5PnDiwau</td>
        <td>sekert1</td>
    </tr>
    <tr>
        <td>/10jpUIdj54uLgvBL0cSlCNmXdV5I5HvvsPLD2Hbin7cdxvWg1Mc</td>
        <td>1234567</td>
    </tr>
    <tr>
        <td>C1hQcfwVa/mIYf0udv/tMegOoPuBdkKqb0/K9USLgutJ1Whg</td>
        <td>9999</td>
    </tr>
</table>


