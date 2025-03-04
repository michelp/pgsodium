# Generating Random Data

``` postgres-console
NOTICE:  extension "pgsodium" already exists, skipping
```

The library provides a set of functions to generate unpredictable data, suitable for creating secret keys.

- On Windows systems, the RtlGenRandom() function is used.
- On OpenBSD and Bitrig, the arc4random() function is used.
- On recent FreeBSD and Linux kernels, the getrandom system call is used.
- On other Unices, the /dev/urandom device is used.
## `randombytes_random()`

Returns a random 32-bit signed integer.
``` postgres-console
select pgsodium.randombytes_random() from generate_series(0, 5);
┌────────────────────┐
│ randombytes_random │
├────────────────────┤
│         1966424117 │
│         -343822918 │
│          584909640 │
│         2142590534 │
│         -506234313 │
│        -1487822225 │
└────────────────────┘
(6 rows)

```
## `randombytes_uniform(upper_bound interger)`

Returns a uniformally distributed random number between zero and the upper bound argument.
``` postgres-console
select pgsodium.randombytes_uniform(10) + 3 from generate_series(0, 5);
┌──────────┐
│ ?column? │
├──────────┤
│       11 │
│        3 │
│       12 │
│        7 │
│        6 │
│        6 │
└──────────┘
(6 rows)

```
## `randombytes_buf(buffer_size integer)`

Returns a random buffer of bytes the size of the argument.
``` postgres-console
select encode(pgsodium.randombytes_buf(10), 'hex') from generate_series(0, 5);
┌──────────────────────┐
│        encode        │
├──────────────────────┤
│ 6dc68e1c77c64c34130b │
│ 763d7aa403c1b7586153 │
│ 531b50a4440ca600f0c7 │
│ a591b41fb13dacbdc056 │
│ 50321fcd231120dd6450 │
│ 00e8aeadcd186a500b59 │
└──────────────────────┘
(6 rows)

```