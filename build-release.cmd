@echo off
set MINGW_DIR=C:\Users\Shadow\AppData\Local\Temp\opencode\mingw\mingw64
set PATH=%MINGW_DIR%\bin;%PATH%
set LIBRARY_PATH=%MINGW_DIR%\x86_64-w64-mingw32\lib
echo Building AETHER SEDC release binaries...
cargo build --release --bin aether
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo Building GUI...
cargo build --release --bin aether-gui
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
echo Done! Binaries in target\release\
dir target\release\aether*.exe
