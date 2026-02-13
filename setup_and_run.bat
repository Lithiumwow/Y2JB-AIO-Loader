@echo off
setlocal enabledelayedexpansion

REM Check if Python is installed
:check_python
echo Checking if Python is installed...
python --version >nul 2>&1
if !errorlevel! equ 0 (
    echo Python is already installed.
    goto create_venv
) else (
    echo Python not found. Installing...
    goto install_python
)

REM Function to download and install Python
:install_python
echo Downloading Python installer...
powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe' -OutFile 'python-installer.exe' -ErrorAction Stop" || (
    echo Failed to download Python installer.
    echo Please install Python manually from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing Python... (This may take a few minutes)
start /wait "" "python-installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
if exist "python-installer.exe" del "python-installer.exe"

REM Refresh PATH after installation
echo Refreshing environment variables...
call :refresh_path

REM Verify installation
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo Python installation failed. Please check:
    echo 1. Antivirus/firewall might be blocking installation
    echo 2. You might need to restart your computer
    pause
    exit /b 1
)
echo Python installation successful.
goto check_python

:refresh_path
set "PATH="
for /f "tokens=2,*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path 2^>nul ^| findstr /i "Path"') do set "PATH=%%b"
for /f "tokens=2,*" %%a in ('reg query "HKCU\Environment" /v Path 2^>nul ^| findstr /i "Path"') do set "PATH=!PATH!;%%b"
exit /b

:create_venv
REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv || (
        echo Failed to create virtual environment.
        echo Try running as Administrator or check disk space
        pause
        exit /b 1
    )
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip || (
    echo Failed to upgrade pip. Continuing anyway...
)

REM Install required dependencies
echo Installing dependencies...
pip install flask flask-cors werkzeug requests || (
    echo Failed to install dependencies.
    call venv\Scripts\deactivate.bat
    pause
    exit /b 1
)

echo Dependencies installed successfully.

REM Run the server
echo Starting server.py...
python server.py

REM Deactivate virtual environment when done
call venv\Scripts\deactivate.bat

echo Server stopped.
pause
exit /b 0