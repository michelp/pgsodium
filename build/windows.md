#### Building on Windows
---------

- Download [libsodium](https://download.libsodium.org/libsodium/releases/libsodium-1.0.18-stable-msvc.zip) >= 1.018 for msvc and unzip
- Download and run the [postgresql installer](https://www.postgresql.org/download/windows/)
- Open the `build/pgsodium_vcxx.sln` solution file in the appropriate version of Visual Studio
- Right click on the project and select `Properties` to bring up the Property Page.
- For all configurations, under `C/C++ -> General -> Additional Include Directories` add the following paths:

```
%PROGRAMFILES%\PostgreSQL\<version>\include\server\port\win32_msvc
%PROGRAMFILES%\PostgreSQL\<version>\include\server\port\win32
%PROGRAMFILES%\PostgreSQL\<version>\include\server
%PROGRAMFILES%\PostgreSQL\<version>\include
{unziped location}\libsodium\include
```

- For all configurations, under `Linker -> General -> Additional Library Directories` add the following paths:

```
{unziped location}\libsodium\x64\Release\v142\dynamic
%PROGRAMFILES%\PostgreSQL\<version>\lib;
```

- Select the `Release` configuration and build
- Rename `pgsodium_vc16.dll` to `pgsodium.dll`
- Copy `libsodium.dll` (usuall in `libsodium\x64\Release\v142\dynamic`) and the newly built `pgsodium.dll` into your `\PostgreSQL\<version>\lib` directory
