@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo           LAN Share - Build
echo ========================================
echo.

py -3.12 --version >nul 2>&1
if errorlevel 1 goto no_python

if not exist ".venv\Scripts\python.exe" (
    echo [1/6] Creating virtual environment...
    py -3.12 -m venv .venv
    if errorlevel 1 goto failed
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto failed

echo [2/6] Updating pip...
python -m pip install --upgrade pip
if errorlevel 1 goto failed

echo [3/6] Installing dependencies...
python -m pip install -r requirements.txt -r requirements-build.txt
if errorlevel 1 goto failed

echo [4/6] Checking Python syntax...
python -m compileall -q main.py lan_share.py core tests
if errorlevel 1 goto failed

echo [5/6] Running unit tests...
python -m unittest discover -s tests -v
if errorlevel 1 goto failed

echo [6/6] Building executable...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
python -m PyInstaller --clean --noconfirm "LAN Share.spec"
if errorlevel 1 goto failed

if not exist "dist\LAN Share.exe" goto missing_exe

echo.
echo BUILD SUCCESS
echo Output: "%CD%\dist\LAN Share.exe"
echo.
pause
exit /b 0

:no_python
echo ERROR: Python 3.12 was not found.
echo Install Python 3.12 and enable the Python Launcher (py.exe).
goto failed

:missing_exe
echo ERROR: PyInstaller finished but the EXE was not found.
goto failed

:failed
echo.
echo BUILD FAILED. Review the error messages above.
pause
exit /b 1
