@ECHO off
setlocal ENABLEDELAYEDEXPANSION
rem !!THIS IS RUN AUTOMATICALLY DURING RELEASE BUILDS, DO NOT RUN MANUALLY!!

SET INSTALLSIZE=0
SET PACKBINS=1

rem Set this to 0 to force disable UPX packing
IF !PACKBINS! EQU 1 (
	WHERE upx
	IF !ERRORLEVEL! NEQ 0 (
		SET PACKBINS=0
		ECHO Can't pack with UPX
	)
)

rem Delete old installer
cd /D %1
IF EXIST "bin\Release\Installer.exe" (
	ECHO Deleting outdated installer
	DEL "bin\Release\Installer.exe"
)

rem Make sure yap.dll was also built
IF EXIST "bin\Release\yap.dll" (

	rem Check if makensis exists
	WHERE makensis
	IF !ERRORLEVEL! EQU 0 (
		ECHO Preparing to build installer
		
		rem Copy required files
		COPY /B /V "Installer\main.nsi" "bin\Release\main.nsi"
		COPY /B /V "Installer\yap.bat" "bin\Release\yap.bat"
		COPY /B /V "SDK\yap.h" "bin\Release\yap.h"
		
		rem Pack release files
		IF !PACKBINS! NEQ 0 (
			ECHO Compressing release files
			upx -9 "bin\Release\asmjit.dll" "bin\Release\glfw3.dll" "bin\Release\yap.dll" "bin\Release\YAPClient.exe" "bin\Release\Zydis.dll"
		)
		
		rem Build
		ECHO Building installer
		FOR /F "usebackq" %%A IN ('bin\Release\Zydis.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\asmjit.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\glfw3.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\YAPClient.exe') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\yap.bat') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\yap.dll') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		FOR /F "usebackq" %%A IN ('bin\Release\yap.h') DO SET /a INSTALLSIZE=INSTALLSIZE+%%~zA
		SET /a INSTALLSIZE=INSTALLSIZE/1000
		makensis /DINSTALLSIZE=!INSTALLSIZE! /V1 "bin\Release\main.nsi"
		IF !ERRORLEVEL! EQU 0 (
			ECHO Finished building installer
		) ELSE (
			ECHO Failed to build installer
		)
		
		rem Clean
		ECHO Cleaning
		DEL "bin\Release\yap.h"
		DEL "bin\Release\yap.bat"
		DEL "bin\Release\main.nsi"
	)
)
endlocal