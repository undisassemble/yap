##### SETUP #####
cmake_minimum_required(VERSION 3.22)
project("Yet Another Packer" LANGUAGES C CXX VERSION 0.0.0 DESCRIPTION "Protector for x64 native Windows PEs.")
if (NOT DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug")
elseif (NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Release"))
	message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either Debug or Release")
endif()
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}/garbage")
configure_file("YAP/include/version.hpp.in" "YAP/include/version.hpp")
configure_file("SDK/yap.h.in" "SDK/yap.h")

# Cross-compilation stuff
set(CMAKE_SYSTEM_NAME Windows)
if (NOT DEFINED WIN32)
	set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
	set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
	set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY) 
	set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
	set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
	include_directories("/usr/x86_64-w64-mingw32/include")
	include_directories("/usr/share/mingw-w64/include")
	link_directories("/usr/x86_64-w64-mingw32/lib")
endif()

# Compiler flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(-Wall)
		add_compile_options(-Wno-write-strings)
		add_compile_options(-Wno-switch)
		add_compile_options(-Wno-sign-compare)
	else()
		add_compile_options(-O3)
		add_compile_options(-w)
	endif()
	add_link_options(-static)
	add_link_options(-Wl,-allow-multiple-definition)
	add_compile_options(-fpermissive)
	add_link_options(-mwindows)
else()
	message(FATAL_ERROR "CMake build files only support clang/gcc")
endif()

# Definitions
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_definitions(_DEBUG)
	add_compile_definitions(ASMJIT_BUILD_DEBUG)
else()
	add_compile_definitions(NDEBUG)
	add_compile_definitions(ASMJIT_BUILD_RELEASE)
endif()
add_compile_definitions(_CONSOLE)
add_compile_definitions(ASMJIT_NO_AARCH64)
add_compile_definitions(ASMJIT_NO_ABI_NAMESPACE)
add_compile_definitions(ASMJIT_NO_DEPRECATED)
add_compile_definitions(_GLFW_WIN32)



##### DEPENDENCIES #####
include_directories(
	"YAP/include"
	"YAP/dependencies"
	"YAP/dependencies/lzma"
	"YAP/dependencies/imgui"
	"YAP/dependencies/imgui/backends"
	"YAP/dependencies/asmjit/src"
	"YAP/dependencies/zydis/include"
	"YAP/dependencies/zydis/src"
	"YAP/dependencies/zydis/dependencies/zycore/include"
	"YAP/dependencies/zydis/dependencies/zycore/src"
	"YAP/dependencies/glfw/include"
)

# glfw
file(GLOB SOURCES_GLFW
	"YAP/dependencies/glfw/src/*.c"
	"YAP/dependencies/glfw/deps/*.c"
)
add_library(glfw3 SHARED ${SOURCES_GLFW})
set_target_properties(glfw3 PROPERTIES PREFIX "")
set_target_properties(glfw3 PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET glfw3 POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:glfw3>)
endif()

# imgui
file(GLOB SOURCES_IMGUI
	"YAP/dependencies/imgui/*.cpp"
	"YAP/dependencies/imgui/backends/imgui_impl_opengl3.cpp"
	"YAP/dependencies/imgui/backends/imgui_impl_glfw.cpp"
)
add_library(imgui SHARED ${SOURCES_IMGUI})
target_link_libraries(imgui glfw3)
set_target_properties(imgui PROPERTIES PREFIX "")
set_target_properties(imgui PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET imgui POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:imgui>)
endif()

# asmjit
file(GLOB SOURCES_ASMJIT
	"YAP/dependencies/asmjit/src/asmjit/core/*.cpp"
	"YAP/dependencies/asmjit/src/asmjit/x86/*.cpp"
)
add_library(asmjit SHARED ${SOURCES_ASMJIT})
set_target_properties(asmjit PROPERTIES PREFIX "")
set_target_properties(asmjit PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET asmjit POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:asmjit>)
endif()

# zydis
file(GLOB SOURCES_ZYDIS
	"YAP/dependencies/zydis/src/*.c"
	"YAP/dependencies/zydis/src/Generated/*.inc"
	"YAP/dependencies/zydis/dependencies/src/*.c"
	"YAP/dependencies/zydis/dependencies/src/API/*.c"
)
add_library(zydis SHARED ${SOURCES_ZYDIS})
set_target_properties(zydis PROPERTIES PREFIX "")
set_target_properties(zydis PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET zydis POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:zydis>)
endif()



##### YAP #####

# yap.dll
add_library(yap SHARED "SDK/yap_sdk.cpp")
set_target_properties(yap PROPERTIES PREFIX "")
set_target_properties(yap PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET yap POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:yap>)
endif()

# YAPClient.exe
file(GLOB SOURCES
	"YAP/src/*.cpp"
	"YAP/dependencies/lzma/*.c"
)
add_executable(YAPClient WIN32 ${SOURCES})
target_link_libraries(YAPClient d3d11)
target_link_libraries(YAPClient shlwapi)
target_link_libraries(YAPClient d3dcompiler)
target_link_libraries(YAPClient dwmapi)
target_link_libraries(YAPClient imgui)
target_link_libraries(YAPClient zydis)
target_link_libraries(YAPClient asmjit)
set_target_properties(YAPClient PROPERTIES PREFIX "")
set_target_properties(YAPClient PROPERTIES SUFFIX ".exe")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET YAPClient POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:YAPClient>)
endif()



##### INSTALLER #####
if (CMAKE_BUILD_TYPE STREQUAL "Release")
	# install(TARGETS YAPClient asmjit imgui zydis glfw3 DESTINATION "bin" RUNTIME)
	# install(TARGETS yap DESTINATION "SDK")
	install(FILES bin/Release/yap.dll SDK/yap.h DESTINATION "SDK")
	install(FILES bin/Release/YAPClient.exe bin/Release/asmjit.dll bin/Release/imgui.dll bin/Release/zydis.dll bin/Release/glfw3.dll Installer/yap.bat DESTINATION "bin")
	set(CPACK_GENERATOR NSIS)
	set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64")
	set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
	# set(CPACK_NSIS_MUI_ICON "INSTALLER ICON")
	# set(CPACK_NSIS_MUI_UNIICON "UNINSTALLER ICON")
	# set(CPACK_NSIS_MUI_HEADERIMAGE "HEADER IMAGE")
	set(CPACK_NSIS_COMPRESSOR "lzma")
	set(CPACK_NSIS_MODIFY_PATH ON)
	set(CPACK_NSIS_DISPLAY_NAME "${CMAKE_PROJECT_NAME}")
	set(CPACK_NSIS_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
	set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/undisassemble/yap")
	# set(CPACK_NSIS_CREATE_ICONS "ON")
	set(CPACK_NSIS_MUI_WELCOMEPAGE_TITLE "Welcome")
	set(CPACK_NSIS_MUI_LICENSEPAGE_TEXT "License Agreement")
	set(CPACK_NSIS_MUI_FINISHPAGE_TITLE "Finished")
	set(CPACK_NSIS_MUI_FINISHPAGE_TEXT "Thank you for installing ${CMAKE_PROJECT_NAME}.")
	set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}")

	include(CPack)
endif()
