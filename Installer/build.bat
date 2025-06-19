@ECHO off
rem Run this to build Installer.exe

setlocal ENABLEDELAYEDEXPANSION
SET INSTALLSIZE=0
ECHO Preparing to build installer

REM Copy required files
COPY /B /V "..\..\Installer\yap.bat" "yap.bat"
COPY /B /V "..\..\Installer\LICENSES" "LICENSE"

REM Calculate installed size
FOR /F "usebackq" %%A IN ('asmjit.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('glfw3.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('imgui.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('LICENSE') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('yap.bat') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('yap.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('yap.h') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('YAPClient.exe') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('Zydis.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('lzma.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
FOR /F "usebackq" %%A IN ('relib.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
SET /a INSTALLSIZE=INSTALLSIZE/1000

REM Build
ECHO Building installer
makensis /DINSTALLSIZE=!INSTALLSIZE! /DVERSION="@PROJECT_VERSION@" /V1 "main.nsi"

endlocal