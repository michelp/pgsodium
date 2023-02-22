#### Building on Windows
---------

- Download [libsodium](https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-msvc.zip) >= 1.018 and unzip
- Download and run the [postgresql installer](https://www.postgresql.org/download/windows/)
- From the `/pgsodium/build` directory, run `msbuild` on `pgsodium.vcxproj`
	- `msbuild` can be invoked though the *x64 Native Tools Command Prompt for VS 2022*

The following properties ( **`/p`** or **`/property`** ) must be specified:
- `libsodiumLocation`: root libsodium directory
- `PostgreSQLLocation`: root postgresql directory, typically `C:\Program Files\PostgreSQL\<version>
- `Configuration`: [`Release`, `Debug`]
- `Platform`: [x64]
- `platformToolset`: [`v142`, `v143`]

ie.

```
msbuild pgsodium.vcxproj /p:libsodiumLocation="C:\libsodium" /p:PostgreSQLLocation="C:\Program Files\PostgreSQL\15" /p:Configuration=Release /p:Platform=x64 /p:platformToolset=v143
```

- Copy the `libsodium.dll` (from `libsodium\x64\Release\<platformToolset>\dynamic`) and the newly built `pgsodium.dll` into your `\PostgreSQL\<version>\lib` directory