#!/bin/bash
# Run this to build installer.exe

INSTALLSIZE=0

# Prep
echo "Preparing to build installer"
cp "../../Installer/yap.bat" "."
cp "../../Installer/LICENSES" "LICENSE"
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "asmjit.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "glfw3.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "imgui.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "YAPClient.exe")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.h")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "Zydis.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "lzma.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "relib.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.bat")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "LICENSE")))
INSTALLSIZE=$(($INSTALLSIZE / 1000))

# Build
echo "Building installer"
makensis -DINSTALLSIZE=$INSTALLSIZE -DVERSION="@PROJECT_VERSION@" -V1 "main.nsi"