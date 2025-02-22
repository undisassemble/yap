#!/bin/bash
# Run this to build installer.exe

INSTALLSIZE=0

# Delete old installer
if [ -f "Installer.exe" ]; then
    echo "Deleting old installer"
    rm "Installer.exe"
fi

# Prep
echo "Preparing to build installer"
cp "../../Installer/yap.bat" "."
cp "../../LICENSE" "."
cp "../../Installer/main.nsi" "."
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "asmjit.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "glfw3.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "imgui.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "YAPClient.exe")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.h")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "zydis.dll")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "yap.bat")))
INSTALLSIZE=$(($INSTALLSIZE + $(stat --printf="%s" "LICENSE")))

# Build
echo "Building installer"
makensis -DINSTALLSIZE=$INSTALLSIZE -V1 "main.nsi"