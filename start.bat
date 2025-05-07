@echo off
setlocal

REM === Settings ===
set PYTHON_URL=https://www.python.org/ftp/python/3.11.8/python-3.11.8-amd64.exe
set PYTHON_INSTALLER=python-installer.exe
set VENV_DIR=.venv
set MAIN_SCRIPT=client.py
set REQUIREMENTS=requirements.txt

REM === Download Python if not installed ===
where py >nul 2>nul
if %errorlevel% neq 0 (
    echo Python not found. Downloading...
    powershell -Command "Invoke-WebRequest -Uri %PYTHON_URL% -OutFile %PYTHON_INSTALLER%"
    echo Installing Python...
    start /wait %PYTHON_INSTALLER% /quiet InstallAllUsers=1 PrependPath=1
    del %PYTHON_INSTALLER%
)

REM === Setup virtual environment ===
if not exist %VENV_DIR%\Scripts\activate (
    echo Creating virtual environment...
    py -m venv %VENV_DIR%
)

REM === Activate venv and install dependencies ===
call %VENV_DIR%\Scripts\activate
pip install --upgrade pip
pip install -r %REQUIREMENTS%

REM === Start the client script ===
python %MAIN_SCRIPT% %*

endlocal
