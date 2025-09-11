@echo off
echo Testing mdmcpsrvr version detection...
echo.
echo 1. Direct version call:
target\debug\mdmcpsrvr.exe --version
echo.
echo 2. Testing mdmcpcfg install with local binary (dry run):
echo (This should detect and parse the version correctly)
echo.
target\debug\mdmcpcfg.exe install --local-path target\debug\mdmcpsrvr.exe --help