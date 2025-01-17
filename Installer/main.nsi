# Setup
!define VERSION "0.0.0"
Name "Yet Another Packer ${VERSION}"
OutFile "Installer.exe"
InstallDir "$PROGRAMFILES64\Yet Another Packer"
RequestExecutionLevel admin
VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Protector for x64 native Windows PEs."
SetCompressor lzma

# Installer
Section
	SetOutPath $INSTDIR
	
	# Program files
	File asmjit.dll
	File glfw3.dll
	File Zydis.dll
	File YAPClient.exe
	File yap.bat
	File yap.dll
	File yap.h
	
	# Other stuff
	CreateShortCut "$SMPROGRAMS\Yet Another Packer.lnk" "$INSTDIR\YAPClient.exe"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "DisplayName" "Yet Another Packer"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "DisplayVersion" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "NoRepair" 1
	!ifdef INSTALLSIZE
		WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "EstimatedSize" ${INSTALLSIZE}
	!endif
	WriteUninstaller $INSTDIR\uninstall.exe
SectionEnd

# Uninstaller
Section "Uninstall"
	Delete $INSTDIR\asmjit.dll
	Delete $INSTDIR\glfw3.dll
	Delete $INSTDIR\Zydis.dll
	Delete $INSTDIR\YAPClient.exe
	Delete $INSTDIR\yap.bat
	Delete $INSTDIR\yap.dll
	Delete $INSTDIR\yap.h
	Delete $INSTDIR\yap.log.txt
	Delete $INSTDIR\yap.config
	Delete "$SMPROGRAMS\Yet Another Packer.lnk"
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP"
	Delete $INSTDIR\uninstall.exe
	RMDir $INSTDIR
SectionEnd