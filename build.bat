@echo off
setlocal
cd /d "%~dp0"

rem Repository settings are environment variables set by config.bat.
call "%~dp0config.bat"
call "%VCVARS64%" >nul 2>&1
if errorlevel 1 exit /b 1

if not exist out mkdir out
if errorlevel 1 exit /b 1

rem Icon generator. Single file, no CRT. It writes out\app_icon.ico.
cl /nologo /O2 /W4 /GS- /Gs262144 /Oi- /Foout\create_icon.obj /Feout\create_icon.exe create_icon.c /link /nologo /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB kernel32.lib
if errorlevel 1 exit /b 1
out\create_icon.exe
if errorlevel 1 exit /b 1

rem Resource script. The icon becomes out\app.res.
rc /nologo /fo out\app.res app.rc
if errorlevel 1 exit /b 1

rem Single-file GUI and its fuzzing self-test. No CRT: the entry commits its own stack.
rem /GS- /Gs262144: no buffer cookie and no __chkstk for frames under 256 KiB.
rem out\app.res is the shortcut icon. --self-test runs the fuzz instead of the lock.
cl /nologo /O2 /W4 /GS- /Gs262144 /Oi- /Foout\baby_screen_lock.obj /Feout\baby_screen_lock.exe baby_screen_lock.c out\app.res /link /nologo /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup /NODEFAULTLIB kernel32.lib user32.lib gdi32.lib ole32.lib
if errorlevel 1 exit /b 1

rem The if-block would expand %errorlevel% before the program runs.
if /I "%~1"=="run" goto run
if /I "%~1"=="test" goto test
exit /b 0

:run
out\baby_screen_lock.exe
exit /b %errorlevel%

:test
out\baby_screen_lock.exe --self-test
exit /b %errorlevel%
