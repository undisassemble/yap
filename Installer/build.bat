@ECHO off
rem Run this to build Installer.exe

setlocal ENABLEDELAYEDEXPANSION

SET INSTALLSIZE=0
REM SET PACKBINS=1

REM Set this to 0 to force disable UPX packing
REM IF !PACKBINS! EQU 1 (
REM 	WHERE upx
REM 	IF !ERRORLEVEL! NEQ 0 (
REM 		SET PACKBINS=0
REM 		ECHO Can't pack with UPX
REM 	)
REM )

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
	SET /a INSTALLSIZE=INSTALLSIZE/1000

	REM Pack release files
	REM IF !PACKBINS! NEQ 0 (
	REM 	ECHO Compressing release files
	REM 	upx -9 "asmjit.dll" "glfw3.dll" "yap.dll" "YAPClient.exe" "Zydis.dll"
	REM )
	
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