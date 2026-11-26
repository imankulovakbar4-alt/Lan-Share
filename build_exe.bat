@echo off
cd /d "%~dp0"

taskkill /f /im "LAN Share.exe" >nul 2>&1
rmdir /s /q build >nul 2>&1
rmdir /s /q dist  >nul 2>&1

py -3.12 -m PyInstaller --noconfirm --onefile --windowed ^
  --workpath "%TEMP%\lanshare_build" ^
  --icon "lan_share.ico" --add-data "lan_share.ico;." ^
  --collect-all tkinterdnd2 ^
  --name "LAN Share" lan_share.py

if errorlevel 1 (
    echo.
    echo BUILD FAILED - see the error above
) else (
    echo.
    echo OK: dist\LAN Share.exe
)
pause