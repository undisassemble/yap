; Setup
!define VERSION "0.0.0"
Name "Yet Another Packer"
OutFile "Installer.exe"
InstallDir "$PROGRAMFILES64\Yet Another Packer"
RequestExecutionLevel admin
VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Protector for x64 native Windows PEs."
SetCompressor lzma

; Installer
Section
    ; bin
    CreateDirectory "$INSTDIR\bin"
    SetOutPath "$INSTDIR\bin"
    File asmjit.dll
    File glfw3.dll
    File zydis.dll
    File imgui.dll
    File lzma.dll
    File YAPClient.exe
    File yap.bat

    ; SDK
    CreateDirectory "$INSTDIR\SDK"
    SetOutPath "$INSTDIR\SDK"
    File yap.dll
    File yap.h

    ; Add to programs list
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "DisplayName" "Yet Another Packer"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "DisplayVersion" "${VERSION}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "NoRepair" 1
	!ifdef INSTALLSIZE
		WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "EstimatedSize" ${INSTALLSIZE}
	!endif

    ; Other files
    CreateShortCut "$SMPROGRAMS\Yet Another Packer.lnk" "$INSTDIR\bin\YAPClient.exe"
    SetOutPath $INSTDIR
    File LICENSE
    WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

; Uninstaller
Section "Uninstall"
    Delete "$SMPROGRAMS\Yet Another Packer.lnk"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP"
    RMDir /r $INSTDIR
SectionEnd