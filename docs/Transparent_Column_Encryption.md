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
print('The new key id is: ', key)
```

    The new key id is:  a7a0449c-0cf6-4563-ac76-934e08508a3d



```python
label = 'ENCRYPT WITH KEY ID ' + str(key)
%sql SECURITY LABEL FOR pgsodium ON COLUMN my_secrets.secret IS :label;
print(label)
```

    ENCRYPT WITH KEY ID a7a0449c-0cf6-4563-ac76-934e08508a3d



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
        <td>cflsdTEru3ieFMc+L8ywWcyWqQUHI8a04L37n26deRxMmY6WxnZl</td>
    </tr>
    <tr>
        <td>+SLLU++WIxM34zMW/usqxNKr4p8+Oj4EkVzBv2WO/5qS9plvNkma</td>
    </tr>
    <tr>
        <td>uMkNgXpvfce5DaMK98AEvXkK7xZQ8hEu5PSq9Vkz9SKq7e7N</td>
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
        <td>cflsdTEru3ieFMc+L8ywWcyWqQUHI8a04L37n26deRxMmY6WxnZl</td>
        <td>sekert1</td>
    </tr>
    <tr>
        <td>+SLLU++WIxM34zMW/usqxNKr4p8+Oj4EkVzBv2WO/5qS9plvNkma</td>
        <td>1234567</td>
    </tr>
    <tr>
        <td>uMkNgXpvfce5DaMK98AEvXkK7xZQ8hEu5PSq9Vkz9SKq7e7N</td>
        <td>9999</td>
    </tr>
</table>


