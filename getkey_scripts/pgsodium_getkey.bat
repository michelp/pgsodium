@echo off
set KEY_FILE="%PGDATA%/pgsodium_root.key"

IF NOT EXIST %KEY_FILE% (
	openssl rand -hex 32 > %KEY_FILE%
)
type "%PGDATA%/pgsodium_root.key"