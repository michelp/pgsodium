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


```sql
%%sql
CREATE TABLE IF NOT EXISTS my_secrets (
  secret text
);
TRUNCATE my_secrets;  -- so the notebook is repeatable with a new key each time
```




    []




```python
key = %sql SELECT * FROM pgsodium.create_key();
key = key[0][0]
label = 'ENCRYPT WITH KEY ID ' + str(key)
print('The security label will be: ', label)
```

    The security label will be:  ENCRYPT WITH KEY ID e5e6de31-8a2a-49ca-a2eb-12bd5d218922



```sql
%%sql 
SECURITY LABEL FOR pgsodium ON COLUMN my_secrets.secret IS :label;
```




    []




```sql
%%sql
INSERT INTO my_secrets (secret) VALUES ('sekert1'), ('1234567'), ('9999');
```




    []




```sql
%%sql
SELECT * FROM my_secrets;
```




<table>
    <tr>
        <th>secret</th>
    </tr>
    <tr>
        <td>5Zzj/xmBZBLRBZQAOXMC4zuxMLqVH+GlsPH3eFZxzO1hx9eg2sx4</td>
    </tr>
    <tr>
        <td>EVjCD2qJTDKMi58/8DGiaOZrFWuqFpznA17yKBJUQT9IAEMQvlT7</td>
    </tr>
    <tr>
        <td>Jc1/2ONBhpsq5FSntN3ZmXXDMNmOAH5VzLVRCjKrk5KaqUk0</td>
    </tr>
</table>




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
        <td>5Zzj/xmBZBLRBZQAOXMC4zuxMLqVH+GlsPH3eFZxzO1hx9eg2sx4</td>
        <td>sekert1</td>
    </tr>
    <tr>
        <td>EVjCD2qJTDKMi58/8DGiaOZrFWuqFpznA17yKBJUQT9IAEMQvlT7</td>
        <td>1234567</td>
    </tr>
    <tr>
        <td>Jc1/2ONBhpsq5FSntN3ZmXXDMNmOAH5VzLVRCjKrk5KaqUk0</td>
        <td>9999</td>
    </tr>
</table>


