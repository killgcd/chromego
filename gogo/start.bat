@echo off
title  GoGo (Web Console: http://127.0.0.1:9092)

set _JAVACMD="java"

rem Detect if java is in PATH.
for /F %%j in ('"%_JAVACMD%" -version  2^>^&1') do (
  if %%~j==java (
    goto _break
  ) else (
    set _JAVACMD=""
    goto _break
  )
)

:_break

if %_JAVACMD%=="" (
    if not "%JAVA_HOME%"=="" (
      if exist "%JAVA_HOME%\bin\java.exe" set _JAVACMD="%JAVA_HOME%\bin\java.exe"
    )
)

if %_JAVACMD%=="" (
  echo.
  echo A Java JRE is not installed or can't be found.
  echo.
  echo Please go to
  echo   http://www.java.com/
  echo and download Java JRE 6 or up version and install before running start.bat.
  echo.
  echo If you think this message is in error, please check
  echo your environment variables to see if "java.exe" is
  echo available via JAVA_HOME or PATH.
  echo.
  pause
  exit /B 1
)

rem run gogo
%_JAVACMD%  -Xmx200m -cp gogo.jar io.gogo.GoGo

pause



