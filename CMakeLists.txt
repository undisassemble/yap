# Setup
cmake_minimum_required(VERSION 3.15)
project(YAP LANGUAGES C CXX VERSION 0.0 DESCRIPTION "Protector for x64 native Windows PEs.")
if (NOT DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug")
elseif (NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Release"))
	message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either Debug or Release")
endif()
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")

# Compiler flags
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(-Wall)
	else()
		add_compile_options(-O3)
		add_compile_options(-w)
	endif()
	add_link_options(-static)
	add_compile_options(-fpermissive)
	add_compile_options(-fmax-errors=3)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	if (CMAKE_BUILD_TYPE STREQUAL "Debug")
		add_compile_options(/W3)
		add_compile_options(/Od)
		add_compile_options(/MTd)
		add_link_options(/INCREMENTAL)
	else()
		add_compile_options(/W0)
		add_compile_options(/O2)
		add_compile_options(/Oi)
		add_compile_options(/Ot)
		add_compile_options(/GL)
		add_compile_options(/MT)
		add_compile_options(/Gy)
		add_link_options(/LTCG:incremental)
		add_link_options(/OPT:ICF)
		add_link_options(/OPT:REF)
	endif()
	add_compile_options(/sdl)
	add_compile_options(/GS)
	add_compile_options(/permissive)
	add_compile_options(/Zc:wchar_t)
	add_compile_options(/Zc:forScope)
	add_compile_options(/Zc:inline)
	add_compile_options(/Gd)
	add_compile_options(/FC)
	add_compile_options(/errorReport:none)
	add_link_options(/DYNAMICBASE)
	add_link_options(/NXCOMPAT)
	add_link_options(/ERRORREPORT:NONE)
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
add_compile_definitions(ZYDIS_STATIC_BUILD)
add_compile_definitions(ZYCORE_STATIC_BUILD)
add_compile_definitions(ASMJIT_NO_AARCH64)
add_compile_definitions(ASMJIT_STATIC)

# yap.dll
add_library(dll MODULE "SDK/yap_sdk.cpp")
set_target_properties(dll PROPERTIES PREFIX "")
set_target_properties(dll PROPERTIES OUTPUT_NAME "yap")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET dll POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:dll>)
endif()

# YAP.exe
file(GLOB SOURCES
	"YAP/*.cpp"
	"YAP/asmjit/src/asmjit/x86/*.cpp"
	"YAP/asmjit/src/asmjit/core/*.cpp"
	"YAP/imgui/*.cpp"
	"YAP/imgui/backends/imgui_impl_win32.cpp"
	"YAP/imgui/backends/imgui_impl_dx11.cpp"
	"YAP/lzma/*.c"
	"YAP/zydis/src/*.c"
	"YAP/zydis/src/Generated/*.inc"
	"YAP/zydis/src/dependencies/zycore/src/*.c"
	"YAP/zydis/src/dependencies/zycore/src/API/*.c"
)
add_executable(exe WIN32 ${SOURCES})
include_directories(
	"YAP"
	"YAP/lzma"
	"YAP/zydis/src"
	"YAP/zydis/include/Zydis"
	"YAP/zydis/dependencies/zycore/include"
	"YAP/asmjit/src/asmjit"
	"YAP/zydis/include"
	"YAP/imgui"
	"YAP/imgui/backends"
)
target_link_libraries(exe d3d11)
target_link_libraries(exe shlwapi)
target_link_libraries(exe d3dcompiler)
target_link_libraries(exe dwmapi)
set_target_properties(exe PROPERTIES PREFIX "")
set_target_properties(exe PROPERTIES OUTPUT_NAME "YAP")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET exe POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:exe>)
endif()