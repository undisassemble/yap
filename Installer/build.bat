@ECHO off
rem Run this to build Installer.exe

setlocal ENABLEDELAYEDEXPANSION

SET INSTALLSIZE=0

REM Delete old installer
IF EXIST "Installer.exe" (
	ECHO Deleting outdated installer
	DEL "Installer.exe"
)

REM Check if makensis exists
WHERE makensis
IF !ERRORLEVEL! EQU 0 (
	ECHO Preparing to build installer
	
	REM Copy required files
	COPY /B /V "..\..\Installer\yap.bat" "yap.bat"
	COPY /B /V "..\..\LICENSE" "LICENSE"
    COPY /B /V "..\..\Installer\main.nsi" "main.nsi"

    REM Calculate installed size
	FOR /F "usebackq" %%A IN ('asmjit.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('glfw3.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('imgui.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('LICENSE') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('yap.bat') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('yap.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('yap.h') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('YAPClient.exe') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('zydis.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	FOR /F "usebackq" %%A IN ('lzma.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
	SET /a INSTALLSIZE=INSTALLSIZE/1000
	
	REM Build
	ECHO Building installer
	makensis /DINSTALLSIZE=!INSTALLSIZE! /V1 "main.nsi"
	IF !ERRORLEVEL! EQU 0 (
		ECHO Finished building installer
	) ELSE (
		ECHO Failed to build installer
	)
) ELSE (
    ECHO "Couldn't find makensis, skipping build."
)
endlocal

pause