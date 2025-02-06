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

# Cross-compilation stuff
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY) 
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
include_directories("/usr/x86_64-w64-mingw32/include")
include_directories("/usr/share/mingw-w64/include")
link_directories("/usr/x86_64-w64-mingw32/lib")

# Compiler flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(-Wall)
        add_link_options(-mconsole)
	else()
		add_compile_options(-O3)
		add_compile_options(-w)
        add_link_options(-mwindows)
	endif()
	add_link_options(-static)
	add_compile_options(-fpermissive)
	add_compile_options(-I/usr/include)
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
add_compile_definitions(GLFW_EXPOSE_NATIVE_WIN32)
add_compile_definitions(_GLFW_WIN32)



##### DEPENDENCIES #####
include_directories(
	"YAP"
	"YAP/lzma"
	"YAP/imgui"
	"YAP/imgui/backends"
	"YAP/asmjit/src"
	"YAP/zydis/include"
	"YAP/zydis/src"
	"YAP/zydis/dependencies/zycore/include"
	"YAP/zydis/dependencies/zycore/src"
	"YAP/glfw/include"
)

# glfw
file(GLOB SOURCES_GLFW
	"YAP/glfw/src/*.c"
	"YAP/glfw/deps/*.c"
)
add_library(glfw3 SHARED ${SOURCES_GLFW})
set_target_properties(glfw3 PROPERTIES PREFIX "")
set_target_properties(glfw3 PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET glfw3 POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:glfw3>)
endif()

# imgui
file(GLOB SOURCES_IMGUI
	"YAP/imgui/*.cpp"
	"YAP/imgui/backends/imgui_impl_opengl3.cpp"
	"YAP/imgui/backends/imgui_impl_glfw.cpp"
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
	"YAP/asmjit/src/asmjit/core/*.cpp"
	"YAP/asmjit/src/asmjit/x86/*.cpp"
)
add_library(asmjit SHARED ${SOURCES_ASMJIT})
set_target_properties(asmjit PROPERTIES PREFIX "")
set_target_properties(asmjit PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET asmjit POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:asmjit>)
endif()

# zydis
file(GLOB SOURCES_ZYDIS
	"YAP/zydis/src/*.c"
	"YAP/zydis/src/Generated/*.inc"
	"YAP/zydis/dependencies/src/*.c"
	"YAP/zydis/dependencies/src/API/*.c"
)
add_library(zydis SHARED ${SOURCES_ZYDIS})
set_target_properties(zydis PROPERTIES PREFIX "")
set_target_properties(zydis PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET zydis POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:zydis>)
endif()



##### YAP #####

# yap.dll
add_library(dll SHARED "SDK/yap_sdk.cpp")
set_target_properties(dll PROPERTIES PREFIX "")
set_target_properties(dll PROPERTIES OUTPUT_NAME "yap")
set_target_properties(dll PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET dll POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:dll>)
endif()

# YAP.exe
file(GLOB SOURCES
	"YAP/*.cpp"
	"YAP/lzma/*.c"
)
add_executable(exe WIN32 ${SOURCES})
target_link_options(exe PRIVATE -municode)
target_link_libraries(exe d3d11)
target_link_libraries(exe shlwapi)
target_link_libraries(exe d3dcompiler)
target_link_libraries(exe dwmapi)
target_link_libraries(exe imgui)
target_link_libraries(exe zydis)
target_link_libraries(exe asmjit)
set_target_properties(exe PROPERTIES PREFIX "")
set_target_properties(exe PROPERTIES OUTPUT_NAME "YAPClient")
set_target_properties(exe PROPERTIES SUFFIX ".exe")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET exe POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:exe>)
endif()



##### INSTALLER ##### https://cmake.org/cmake/help/latest/cpack_gen/nsis.html
if (CMAKE_BUILD_TYPE STREQUAL "Release")
	install(TARGETS exe dll asmjit imgui zydis glfw3 DESTINATION bin RUNTIME)
	install(FILES SDK/yap.h Installer/yap.bat DESTINATION bin)
	set(CPACK_GENERATOR NSIS)
	set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES64\\${CMAKE_PROJECT_NAME}")
	# set(CPACK_NSIS_MUI_ICON "INSTALLER ICON")
	# set(CPACK_NSIS_MUI_UNIICON "UNINSTALLER ICON")
	set(CPACK_NSIS_COMPRESSOR "lzma")
	set(CPACK_NSIS_MODIFY_PATH ON)
	set(CPACK_NSIS_DISPLAY_NAME "${CMAKE_PROJECT_NAME}")
	set(CPACK_NSIS_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
	set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/undisassemble/yap")
	include(CPack)
endif()