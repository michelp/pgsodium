# Configuration

pgsodium can be used in two ways:

- either as a "pure" library extension with no server managed keys that you can load into your SQL session at any time with the `LOAD` command

- "preload" mode where you place `pgsodium` in your postgres server's `shared_preload_libraries` configuration variable.
