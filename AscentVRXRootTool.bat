@echo off
setlocal EnableExtensions
cd /d "%~dp0"

rem Find a working Python 3.10+ interpreter. "python" may be the Microsoft
rem Store alias stub, which does not actually run Python, so probe it first
rem and fall back to the real launcher.
set "PYTHON_CMD="
set "STORE_ALIAS=0"
set "OLD_PYTHON=0"
set "AUTO_YES=0"
set "NO_WINGET=0"

rem Never let a probe silently download a runtime; ask before installing.
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=0"

rem --yes / -y also means "do not stop for the Python install prompt".
for %%a in (%*) do (
    if /i "%%~a"=="--yes" set "AUTO_YES=1"
    if /i "%%~a"=="-y" set "AUTO_YES=1"
)

call :probe_python
if defined PYTHON_CMD goto :run

call :detect_store_alias

rem If winget (App Installer) is available, offer to install Python through
rem the official Python Install Manager. No Python needed to run this.
where winget >nul 2>&1
if errorlevel 1 set "NO_WINGET=1"

if "%NO_WINGET%"=="1" goto :manual_python

if "%AUTO_YES%"=="1" (
    echo.
    echo   Python is missing; --yes installs it with winget.
    goto :do_install
)

call :show_problem
choice /c yn /n /m "  Install Python now with winget? [Y/n] "
if errorlevel 2 goto :manual_python

:do_install
call :install_python
if not defined PYTHON_CMD goto :install_failed

echo.
echo   Python is ready.
goto :run

:run
for /f "delims=" %%v in ('%PYTHON_CMD% --version 2^>^&1') do echo   %%v
%PYTHON_CMD% root_tool.py %*
set "EXITCODE=%errorlevel%"
goto :finish

rem ============================================================
rem Interpreter detection
rem ============================================================

:probe_python
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 3)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    exit /b 0
)
rem Exit code 3 means a real Python answered but it is older than 3.10.
if errorlevel 3 if not errorlevel 4 set "OLD_PYTHON=1"

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 3)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py -3"
    exit /b 0
)
if errorlevel 3 if not errorlevel 4 set "OLD_PYTHON=1"

rem Last resort: the install manager can run the default runtime even when
rem the "python" and "py" aliases are shadowed or disabled.
pymanager exec -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 3)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=pymanager exec"
    exit /b 0
)
if errorlevel 3 if not errorlevel 4 set "OLD_PYTHON=1"

set "PYTHON_CMD="
exit /b 1

:detect_store_alias
where python >nul 2>&1
if errorlevel 1 exit /b 0
where python 2>nul | find /i "WindowsApps" >nul
if not errorlevel 1 set "STORE_ALIAS=1"
exit /b 0

rem ============================================================
rem Messages
rem ============================================================

:show_problem
set "PROBLEM_SHOWN=1"
echo.
echo ============================================================
echo   Python 3.10 or newer is required but was not found.
echo ============================================================
echo.
if "%STORE_ALIAS%"=="1" (
    echo   "python" resolves to a Windows app execution alias that
    echo   does not run Python. This is usually the Microsoft Store
    echo   stub, not a real Python installation.
    echo.
)
if "%OLD_PYTHON%"=="1" (
    echo   A Python installation was found, but it is older than 3.10.
    echo.
)
if "%NO_WINGET%"=="0" (
    echo   This launcher can install Python for you using winget:
    echo     - Python Install Manager, the official manager from python.org
    echo     - the latest Python 3 runtime
    echo.
    echo   It needs internet access and the winget / App Installer app.
    echo.
    echo   Prefer a normal installer? Download Python 3.10+ from:
    echo     https://www.python.org/downloads/windows/
    echo.
)
exit /b 0

:manual_python
if not defined PROBLEM_SHOWN call :show_problem
echo.
if "%NO_WINGET%"=="1" (
    echo   winget is not available on this PC. Install "App Installer"
    echo   from the Microsoft Store, or install Python from:
    echo     https://www.python.org/downloads/windows/
) else (
    echo   Install Python 3.10 or newer manually with:
    echo.
    echo     winget install 9NQ7512CXL7T -e
    echo     py install 3
)
echo.
if "%STORE_ALIAS%"=="1" (
    echo   If "python" keeps opening the Microsoft Store:
    echo     Settings ^> Apps ^> Advanced app settings
    echo     ^> App execution aliases
    echo   Turn OFF "python.exe" and "python3.exe", then install Python.
    echo.
)
echo   During setup, tick "Add python.exe to PATH".
echo   Then close this window and run AscentVRXRootTool.bat again.
echo.
set "EXITCODE=1"
goto :finish

:install_failed
echo.
echo   The automatic install did not finish successfully.
echo   Common causes: no internet, winget or App Installer missing,
echo   the Microsoft Store blocked by policy, or Python 3.10+ not
echo   actually being installed.
goto :manual_python

rem ============================================================
rem Automatic installation (Python Install Manager via winget)
rem ============================================================

:install_python
echo.
echo   Installing the Python Install Manager with winget...
winget install 9NQ7512CXL7T -e --accept-package-agreements --accept-source-agreements --disable-interactivity
if errorlevel 1 exit /b 1

rem The aliases live in WindowsApps; make sure this session can see them
rem even if the installer changed PATH after this console started.
set "PATH=%LocalAppData%\Microsoft\WindowsApps;%LocalAppData%\Python\bin;%PATH%"

echo.
echo   Installing the latest Python 3 runtime...
pymanager install -y 3
if errorlevel 1 py install -y 3
if errorlevel 1 exit /b 1

call :probe_python
if not defined PYTHON_CMD exit /b 1
exit /b 0

:finish
rem Keep the window open for real errors, but not after a normal cancel (130).
if not "%EXITCODE%"=="0" if not "%EXITCODE%"=="130" (
    echo.
    pause
)
exit /b %EXITCODE%
