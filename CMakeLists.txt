##### SETUP #####
cmake_minimum_required(VERSION 3.22)
enable_testing()
project("Yet Another Packer" LANGUAGES C CXX VERSION 0.0.0 DESCRIPTION "Protector for x64 native Windows PEs.")
if (NOT DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug")
elseif (NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Release"))
	message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either Debug or Release")
endif()
find_package(Python3 REQUIRED)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "bin/${CMAKE_BUILD_TYPE}/garbage")
option(ENABLE_DUMPING "Enable option to dump disassembly in debug builds (uses more memory)" OFF)

# Versioning stuff
configure_file("YAP/include/version.hpp.in" "YAP/include/version.hpp")
configure_file("YAP/meta/YAPClient.rc.in" "YAP/meta/YAPClient.rc")
configure_file("SDK/yap.h.in" "SDK/yap.h")
configure_file("SDK/yap.rc.in" "SDK/yap.rc")

# Cross-compilation stuff
set(CMAKE_SYSTEM_NAME Windows)
if (NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
	set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
	set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
	set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY) 
	set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
	set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
	set(CROSSCOMPILING_EMULATOR wine)
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

# glfw3
file(GLOB SOURCES_GLFW
	"YAP/dependencies/glfw/src/*.c"
	"YAP/dependencies/glfw/deps/*.c"
	"YAP/meta/glfw3.rc"
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
	"YAP/meta/imgui.rc"
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
	"YAP/meta/asmjit.rc"
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
	"YAP/dependencies/zydis/dependencies/zycore/src/*.c"
	"YAP/dependencies/zydis/dependencies/zycore/src/API/*.c"
	"YAP/dependencies/zydis/resources/VersionInfo.rc"
)
add_library(zydis SHARED ${SOURCES_ZYDIS})
set_target_properties(zydis PROPERTIES PREFIX "")
set_target_properties(zydis PROPERTIES SUFFIX ".dll")
target_compile_definitions(zydis PUBLIC ZYCORE_SHOULD_EXPORT)
target_compile_definitions(zydis PUBLIC ZYDIS_SHOULD_EXPORT)
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET zydis POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:zydis>)
endif()

# lzma
file(GLOB SOURCES_LZMA
	"YAP/dependencies/lzma/*.c"
	"YAP/meta/lzma.rc"
)
add_library(lzma SHARED ${SOURCES_LZMA})
set_target_properties(lzma PROPERTIES PREFIX "")
set_target_properties(lzma PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET lzma POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:lzma>)
endif()



##### YAP #####

# yap.dll
add_library(yap SHARED "SDK/yap_sdk.cpp" "SDK/yap.rc")
set_target_properties(yap PROPERTIES PREFIX "")
set_target_properties(yap PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET yap POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:yap>)
endif()

# Generate includes
file(GLOB SOURCES_ASM "YAP/src/modules/*.asm")
add_custom_command(OUTPUT "YAP/include/modules/anti-dump.inc" MAIN_DEPENDENCY ${CMAKE_CURRENT_BINARY_DIR}/generate_asm.py  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/generate_asm.py DEPENDS ${SOURCES_ASM})
add_custom_target(Generated ALL DEPENDS "YAP/include/modules/anti-dump.inc")

# YAPClient.exe
file(GLOB SOURCES
	"YAP/src/*.cpp"
	"YAP/meta/YAPClient.rc"
)
add_executable(YAPClient WIN32 ${SOURCES})
add_dependencies(YAPClient Generated)
target_link_libraries(YAPClient d3d11)
target_link_libraries(YAPClient ntdll)
target_link_libraries(YAPClient shlwapi)
target_link_libraries(YAPClient dbghelp)
target_link_libraries(YAPClient d3dcompiler)
target_link_libraries(YAPClient dwmapi)
target_link_libraries(YAPClient opengl32)
target_link_libraries(YAPClient imgui)
target_link_libraries(YAPClient zydis)
target_link_libraries(YAPClient asmjit)
target_link_libraries(YAPClient lzma)
set_target_properties(YAPClient PROPERTIES PREFIX "")
set_target_properties(YAPClient PROPERTIES SUFFIX ".exe")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET YAPClient POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:YAPClient> "bin/${CMAKE_BUILD_TYPE}/YAPClient.dbg")
	add_custom_command(TARGET YAPClient POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:YAPClient>)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND ENABLE_DUMPING)
	message(STATUS "Enabled reasm dumps")
	target_compile_definitions(YAPClient PUBLIC ENABLE_DUMPING)
endif()

##### INSTALLER #####
if (CMAKE_BUILD_TYPE STREQUAL "Release")
	# Create zip
	install(FILES bin/Release/yap.dll SDK/yap.h DESTINATION "SDK")
	install(FILES bin/Release/YAPClient.exe bin/Release/asmjit.dll bin/Release/imgui.dll bin/Release/zydis.dll bin/Release/glfw3.dll bin/Release/lzma.dll Installer/yap.bat DESTINATION "bin")
	install(FILES LICENSE DESTINATION ".")
	set(CPACK_GENERATOR ZIP)
	set(CPACK_PACKAGE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/${CMAKE_BUILD_TYPE}")
	include(CPack)

	# Create installer
	find_program(NSIS_PATH makensis)
	if (NOT NSIS_PATH)
		message(WARNING "makensis command not found, skipping installer.")
	else()
		configure_file("SDK/yap.h.in" "bin/Release/yap.h")
		if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
			file(COPY "Installer/build.bat" DESTINATION "bin/Release")
		else()
			file(COPY "Installer/build.sh" DESTINATION "bin/Release")
		endif()
	endif()
endif()

##### TESTS #####

# Build test executable
add_executable(test_executable WIN32 tests/test.cpp)
set_target_properties(test_executable PROPERTIES PREFIX "")
set_target_properties(test_executable PROPERTIES SUFFIX ".exe")

# Test function
function(run_test yaproj)
    add_test(NAME "Protect (easy) - ${yaproj}" COMMAND ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:YAPClient> ${PROJECT_SOURCE_DIR}/tests/${yaproj}.yaproj protect $<TARGET_FILE:test_executable> ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        add_test(NAME "Run (easy) - ${yaproj}" COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
    endif()
	add_test(NAME "Protect (hard) - ${yaproj}" COMMAND ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:YAPClient> ${PROJECT_SOURCE_DIR}/tests/${yaproj}.yaproj protect $<TARGET_FILE:YAPClient> ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
	if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
        add_test(NAME "Run (hard) - ${yaproj}" COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
    endif()
endfunction()

# Packer tests
run_test(packer/0)
run_test(packer/1)
run_test(packer/2)
run_test(packer/3)
run_test(packer/4)
run_test(packer/5)
run_test(packer/6)
run_test(packer/7)
run_test(packer/all)

# Reassembler tests
run_test(reasm/0)
run_test(reasm/1)
run_test(reasm/2)
run_test(reasm/3)
run_test(reasm/all)

# Combo tests
run_test(combo/packer-reasm/0)
run_test(combo/packer-reasm/1)
run_test(combo/packer-reasm/2)
run_test(combo/packer-reasm/3)
run_test(combo/packer-reasm/all)
run_test(combo/packer-reasm/partial_loading)