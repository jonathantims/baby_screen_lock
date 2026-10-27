@echo off
rem ======================================================================
rem  config.bat — repository configuration.
rem
rem  Machine-specific settings live here as environment variables.
rem  build.bat calls this script and then uses the variables it set.
rem  Do not add setlocal: the caller's environment is what that script
rem  reads.
rem
rem  A variable that is already set is left unchanged. Set it in the
rem  environment before the build for a one-off override, or edit the
rem  default below for this machine.
rem
rem  Variables
rem
rem  VCVARS64
rem    Full path of Visual Studio's x64 developer script, vcvars64.bat.
rem    After this script returns, the build calls that path. The call
rem    puts cl and link on PATH and sets LIB and INCLUDE.
rem    The default is Visual Studio 2022 Community.
rem ======================================================================
if "%VCVARS64%"=="" set "VCVARS64=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
