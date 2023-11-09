# Generating Random Data

The library provides a set of functions to generate unpredictable data, suitable for creating secret keys.

- On Windows systems, the RtlGenRandom() function is used.
- On OpenBSD and Bitrig, the arc4random() function is used.
- On recent FreeBSD and Linux kernels, the getrandom system call is used.
- On other Unices, the /dev/urandom device is used.


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



### `randombytes_random()`

Returns a random 32-bit signed integer.


```python
%sql select pgsodium.randombytes_random() from generate_series(0, 5);
```




<table>
    <tr>
        <th>randombytes_random</th>
    </tr>
    <tr>
        <td>-790657505</td>
    </tr>
    <tr>
        <td>970732090</td>
    </tr>
    <tr>
        <td>934314631</td>
    </tr>
    <tr>
        <td>-915187547</td>
    </tr>
    <tr>
        <td>-227520694</td>
    </tr>
    <tr>
        <td>934389461</td>
    </tr>
</table>



### `randombytes_uniform(upper_bound integer)`

Returns a uniformally distributed random number between zero and the upper bound argument.


```python
%sql select pgsodium.randombytes_uniform(10) + 3 from generate_series(0, 5);
```




<table>
    <tr>
        <th>?column?</th>
    </tr>
    <tr>
        <td>9</td>
    </tr>
    <tr>
        <td>9</td>
    </tr>
    <tr>
        <td>12</td>
    </tr>
    <tr>
        <td>5</td>
    </tr>
    <tr>
        <td>3</td>
    </tr>
    <tr>
        <td>12</td>
    </tr>
</table>



### `randombytes_buf(buffer_size integer)`

Returns a random buffer of bytes the size of the argument.


```python
%sql select encode(pgsodium.randombytes_buf(10), 'hex') from generate_series(0, 5);
```




<table>
    <tr>
        <th>encode</th>
    </tr>
    <tr>
        <td>6d995ff6597b8caa05a0</td>
    </tr>
    <tr>
        <td>5e7aa28d67c37e3c8cea</td>
    </tr>
    <tr>
        <td>1e3c8cdc8d5836817947</td>
    </tr>
    <tr>
        <td>7dac87837187143884b3</td>
    </tr>
    <tr>
        <td>fdd853c4111a624d6d92</td>
    </tr>
    <tr>
        <td>656962919682a665596d</td>
    </tr>
</table>


