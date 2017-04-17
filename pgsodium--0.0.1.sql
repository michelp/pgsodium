-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgsodium" to load this file. \quit

CREATE FUNCTION pgsodium_randombytes_random()
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_randombytes_uniform(integer)
RETURNS integer
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION pgsodium_randombytes_buf(integer)
RETURNS bytea
AS '$libdir/pgsodium'
LANGUAGE C IMMUTABLE STRICT;


