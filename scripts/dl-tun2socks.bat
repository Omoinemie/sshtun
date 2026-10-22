@echo off
setlocal EnableDelayedExpansion

rem ==============================================================
rem  dl-tun2socks.bat - download the latest tun2socks and wintun.dll
rem
rem  Usage:
rem    dl-tun2socks.bat
rem
rem  Downloads into the current directory:
rem    tun2socks.exe   the tun2socks core
rem    wintun.dll      the Windows TUN driver
rem
rem  Environment variables:
rem    T2S_VERSION   pin a version (e.g. v2.7.0). Empty = latest.
rem    GH_MIRROR     GitHub mirror prefix (e.g. https://ghfast.top).
rem                   Several may be given, space separated, tried in order.
rem
rem  Notes:
rem    This script is for Windows, and needs neither sshtun nor a Go
rem    toolchain. Linux users should use dl-tun2socks.sh instead.
rem ==============================================================

set "REPO=xjasonlyu/tun2socks"
set "API=https://api.github.com/repos/%REPO%/releases/latest"
set "GHDL=https://github.com/%REPO%/releases/download"
set "WINTUN_URL=https://www.wintun.net/builds/wintun-0.14.1.zip"
set "MIRRORS=%GH_MIRROR%"
if not defined MIRRORS set "MIRRORS=https://ghfast.top https://ghproxy.net https://gh-proxy.com"

set "ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" set "ARCH=386"
set "ASSET=tun2socks-windows-%ARCH%.zip"

where curl >nul 2>&1
if errorlevel 1 (
    echo [x] curl not found - it ships with Windows 10 1803 and later.
    exit /b 1
)

rem Double-clicking the script would close the window as soon as it exits,
rem hiding the output (e.g. "already up to date"). Detect that case and
rem pause before leaving. Running it from an existing prompt keeps the
rem prompt intact, so no pause is needed there.
set "PAUSE_AT_END="
echo %cmdcmdline% | find /i "%~nx0" >nul 2>&1 && set "PAUSE_AT_END=1"

set "EXITCODE=0"
set "TMP=%TEMP%\sshtun-fetch-%RANDOM%%RANDOM%"
mkdir "%TMP%" >nul 2>&1

rem ---------- 1. local version ----------
set "LOCAL="
if exist "tun2socks.exe" (
    for /f "usebackq tokens=2 delims=-" %%v in (`tun2socks.exe --version 2^>nul`) do (
        if not defined LOCAL set "LOCAL=%%v"
    )
)

rem ---------- 2. latest version ----------
set "TAG="
if defined T2S_VERSION (
    set "TAG=%T2S_VERSION%"
) else (
    call :latest_tag
)
if not defined TAG (
    echo [x] Could not resolve the latest version.
    echo     Set T2S_VERSION to pin one, e.g. set T2S_VERSION=v2.7.0
    set "EXITCODE=1"
    goto :finish
)
if not "!TAG:~0,1!"=="v" set "TAG=v!TAG!"
set "LATEST=!TAG:~1!"

rem ---------- 3. compare versions ----------
if "!LOCAL!"=="!LATEST!" (
    echo   tun2socks is already at the latest version v!LATEST!, nothing to do.
    goto :finish
)
echo   tun2socks v!LOCAL! -^> v!LATEST!

rem ---------- 4. download ----------
set "URLS=%GHDL%/%TAG%/%ASSET%"
for %%M in (%MIRRORS%) do set "URLS=!URLS! %%M/%GHDL%/%TAG%/%ASSET%"

set "ZIP=%TMP%\%ASSET%"
set "DOWNLOADED="
for %%U in (!URLS!) do (
    if not defined DOWNLOADED (
        echo   downloading %%U
        curl -fsSL --connect-timeout 20 --max-time 900 -H "User-Agent: sshtun" -o "%ZIP%" "%%U"
        if not errorlevel 1 set "DOWNLOADED=1"
    )
)
if not defined DOWNLOADED (
    echo [x] Failed to download tun2socks. Check the network or set GH_MIRROR.
    set "EXITCODE=1"
    goto :finish
)

rem ---------- 5. unpack into the current directory ----------
echo   unpacking...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ZIP%' -DestinationPath '%TMP%\x' -Force" >nul 2>&1
if errorlevel 1 (
    echo [x] Failed to unpack the archive.
    set "EXITCODE=1"
    goto :finish
)

set "FOUND="
for /f "usebackq delims=" %%F in (`dir /b /s "%TMP%\x\tun2socks*.exe" 2^>nul`) do (
    if not defined FOUND (
        set "FOUND=1"
        copy /y "%%F" "tun2socks.exe" >nul
    )
)
if not defined FOUND (
    echo [x] The archive did not contain a tun2socks executable.
    set "EXITCODE=1"
    goto :finish
)

rem ---------- 6. wintun.dll ----------
echo   downloading wintun.dll
curl -fsSL --connect-timeout 20 --max-time 300 -o "%TMP%\w.zip" "%WINTUN_URL%" >nul 2>&1
if errorlevel 1 (
    echo [x] Failed to download wintun.dll.
    set "EXITCODE=1"
    goto :finish
)

echo   unpacking...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%TMP%\w.zip' -DestinationPath '%TMP%\w' -Force" >nul 2>&1
if errorlevel 1 (
    echo [x] Failed to unpack the wintun archive.
    set "EXITCODE=1"
    goto :finish
)

set "WT_ARCH=%ARCH%"
if /i "%ARCH%"=="386" set "WT_ARCH=x86"
if not exist "%TMP%\w\wintun\bin\%WT_ARCH%\wintun.dll" (
    echo [x] wintun.dll for %WT_ARCH% not found in the archive.
    set "EXITCODE=1"
    goto :finish
)
copy /y "%TMP%\w\wintun\bin\%WT_ARCH%\wintun.dll" "wintun.dll" >nul

echo.
echo   done:
echo     %CD%\tun2socks.exe
echo     %CD%\wintun.dll
echo.

rem ==============================================================
rem  :finish - clean up and exit, pausing first when the script was
rem            launched by double-click (the window would otherwise vanish).
rem ==============================================================
:finish
rmdir /s /q "%TMP%" >nul 2>&1
if defined PAUSE_AT_END (
    echo.
    pause
)
endlocal & exit /b %EXITCODE%

rem ==============================================================
rem  :latest_tag - resolve the newest published version into TAG.
rem ==============================================================
:latest_tag
rem Preferred: the GitHub API.
curl -fsSL --connect-timeout 20 -o "%TMP%\rel.json" "%API%" >nul 2>&1
if exist "%TMP%\rel.json" (
    for /f "usebackq tokens=2 delims=:, " %%t in (`findstr /c:"tag_name" "%TMP%\rel.json"`) do (
        if not defined TAG set "TAG=%%~t"
    )
)
if defined TAG goto :eof

rem Fallback: the releases/latest redirect, which avoids the API entirely.
for /f "usebackq tokens=2 delims= " %%L in (`curl -fsSI --connect-timeout 20 "%GHDL%/latest" ^| findstr /i "^location:"`) do (
    if not defined LOC set "LOC=%%L"
)
if not defined LOC goto :eof
set "TAIL=!LOC:*tag/=!"
for /f "usebackq tokens=* delims=/" %%A in ("!TAIL!") do set "TAG=%%A"
goto :eof
