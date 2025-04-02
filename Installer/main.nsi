; Defines
!define VERSION "0.0.0"
Name "Yet Another Packer"
OutFile "YAP-${VERSION}-Installer.exe"
InstallDir "$PROGRAMFILES64\Yet Another Packer"
RequestExecutionLevel admin
SetCompressor lzma

;----- MUI2 -----;
!include MUI2.nsh

; Icons
; !define MUI_ICON "" ; FOR WHEN ICON IS ADDED
; !define MUI_UNICON "" ; FOR WHEN ICON IS ADDED
; !define MUI_HEADERIMAGE_BITMAP "" ; FOR WHEN ICON IS ADDED

; Settings
!define MUI_ABORTWARNING
!define MUI_UNABORTWARNING

; Pages
var SMF
!insertmacro MUI_PAGE_WELCOME
!define MUI_LICENSEPAGE_CHECKBOX
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU 0 $SMF
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\bin\YAPClient.exe"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_DIRECTORY
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
;----------------;

; File version
VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Protector for AMD64 native Windows PEs."

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
		WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP" "EstimatedSize" $INSTALLSIZE
	!endif

    ; Other files
    !insertmacro MUI_STARTMENU_WRITE_BEGIN 0
        CreateDirectory "$SMPROGRAMS\$SMF"
        CreateShortCut "$SMPROGRAMS\$SMF\Yet Another Packer.lnk" "$INSTDIR\bin\YAPClient.exe"
    !insertmacro MUI_STARTMENU_WRITE_END
    SetOutPath $INSTDIR
    File LICENSE
    WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

; Uninstaller
Section "Uninstall"
    RMDir /r "$SMPROGRAMS\$SMF"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\YAP"
    RMDir /r $INSTDIR
SectionEnd