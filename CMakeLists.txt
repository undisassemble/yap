##### SETUP #####
cmake_minimum_required(VERSION 3.22)
enable_testing()

# Cross-compilation stuff
set(CMAKE_SYSTEM_NAME Windows)
if (NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
	set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
	set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
	set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY) 
	set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
	set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
	find_program(wine_exec wine)
	if (wine_exec)
		set(CROSSCOMPILING_EMULATOR "${wine_exec}")
	else()
		message(WARNING "Wine is not installed, testing disabled")
	endif()
	include_directories("/usr/x86_64-w64-mingw32/include")
	include_directories("/usr/share/mingw-w64/include")
	link_directories("/usr/x86_64-w64-mingw32/lib")
endif()

# Other setup
project("Yet Another Packer" LANGUAGES C CXX VERSION 0.0.0 DESCRIPTION "Protector for AMD64 native Windows PEs.")
if (NOT DEFINED CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE "Debug")
elseif (NOT (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "Release"))
	message(FATAL_ERROR "CMAKE_BUILD_TYPE must be either Debug or Release")
endif()
find_package(Python3 REQUIRED)
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}/garbage")

# Versioning stuff
configure_file("YAP/include/version.hpp.in" "YAP/include/version.hpp")
configure_file("YAP/meta/YAPClient.rc.in" "YAP/meta/YAPClient.rc")
configure_file("SDK/yap.h.in" "SDK/yap.h")
configure_file("SDK/yap.rc.in" "SDK/yap.rc")

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
else()
	message(FATAL_ERROR "CMake build files only support clang/gcc")
endif()

# Definitions
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	add_compile_definitions(_DEBUG)
else()
	add_compile_definitions(NDEBUG)
endif()
add_compile_definitions(_CONSOLE)



##### DEPENDENCIES #####

# glfw3
file(GLOB SOURCES_GLFW
	"YAP/dependencies/glfw/src/*.c"
	"YAP/dependencies/glfw/deps/*.c"
	"YAP/meta/glfw3.rc"
)
add_library(glfw3 SHARED ${SOURCES_GLFW})
target_include_directories(glfw3 AFTER PUBLIC "YAP/dependencies/glfw/include")
target_link_options(glfw3 PUBLIC -mwindows)
target_compile_definitions(glfw3 PUBLIC _GLFW_WIN32)
set_target_properties(glfw3 PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET glfw3 POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:glfw3> "bin/${CMAKE_BUILD_TYPE}/glfw3.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:glfw3>)
endif()

# imgui
file(GLOB SOURCES_IMGUI
	"YAP/dependencies/imgui/*.cpp"
	"YAP/dependencies/imgui/backends/imgui_impl_opengl3.cpp"
	"YAP/dependencies/imgui/backends/imgui_impl_glfw.cpp"
	"YAP/meta/imgui.rc"
)
add_library(imgui SHARED ${SOURCES_IMGUI})
target_include_directories(imgui AFTER PUBLIC "YAP/dependencies/imgui" "YAP/dependencies/imgui/backends")
target_link_options(imgui PUBLIC -mwindows)
target_link_libraries(imgui glfw3)
set_target_properties(imgui PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET imgui POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:imgui> "bin/${CMAKE_BUILD_TYPE}/imgui.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:imgui>)
endif()

# lzma
file(GLOB SOURCES_LZMA
	"YAP/dependencies/lzma/*.c"
	"YAP/meta/lzma.rc"
)
add_library(lzma SHARED ${SOURCES_LZMA})
target_include_directories(lzma AFTER PUBLIC "YAP/dependencies/lzma")
target_link_options(lzma PUBLIC -mwindows)
set_target_properties(lzma PROPERTIES SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET lzma POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:lzma> "bin/${CMAKE_BUILD_TYPE}/lzma.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:lzma>)
endif()

# relib
add_subdirectory("YAP/dependencies/relib")


##### YAP #####

# yap.dll
add_library(yap SHARED "SDK/yap_sdk.cpp" "SDK/yap.rc")
target_link_options(yap PUBLIC -mwindows)
set_target_properties(yap PROPERTIES PREFIX "" SUFFIX ".dll")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET yap POST_BUILD COMMAND ${CMAKE_STRIP} $<TARGET_FILE:yap>)
endif()

# Generate includes
file(GLOB SOURCES_ASM "YAP/src/modules/*.asm")
add_custom_target(Generated ${Python3_EXECUTABLE} "${CMAKE_CURRENT_BINARY_DIR}/generate_asm.py" DEPENDS ${SOURCES_ASM})

# YAPClient.exe
file(GLOB SOURCES
	"YAP/src/*.cpp"
	"YAP/meta/YAPClient.rc"
)
add_executable(YAPClient WIN32 ${SOURCES})
add_dependencies(YAPClient Generated)
target_include_directories(YAPClient PRIVATE "YAP/include")
target_link_options(YAPClient PUBLIC -mwindows)
target_compile_definitions(YAPClient PUBLIC _GLFW_WIN32)
target_link_libraries(YAPClient d3d11 ntdll shlwapi dbghelp d3dcompiler dwmapi opengl32 imgui lzma relib)
set_target_properties(YAPClient PROPERTIES PREFIX "" SUFFIX ".exe")
if (DEFINED CMAKE_STRIP AND CMAKE_BUILD_TYPE STREQUAL "Release")
	add_custom_command(TARGET YAPClient POST_BUILD COMMAND objcopy --only-keep-debug $<TARGET_FILE:YAPClient> "bin/${CMAKE_BUILD_TYPE}/YAPClient.dbg" COMMAND ${CMAKE_STRIP} $<TARGET_FILE:YAPClient>)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug" AND ENABLE_DUMPING)
	message(STATUS "Enabled reasm dumps")
	target_compile_definitions(YAPClient PUBLIC ENABLE_DUMPING)
endif()

##### EXTRA #####
if (CMAKE_BUILD_TYPE STREQUAL "Release")
	# Create installer
	find_program(NSIS_PATH makensis)
	if (NSIS_PATH)
		message(STATUS "Will build installer")
		configure_file("SDK/yap.h.in" "bin/Release/yap.h")
		file(COPY "Installer/main.nsi" DESTINATION "bin/Release")
		if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
			configure_file("Installer/build.bat" "bin/Release/build.bat")
			set(INSTALLER_SCRIPT "build.bat")
		else()
			configure_file("Installer/build.sh" "bin/Release/build.sh")
			set(INSTALLER_SCRIPT "./build.sh")
		endif()
		add_custom_target(installer ALL ${INSTALLER_SCRIPT} DEPENDS "Installer/main.nsi" BYPRODUCTS "${INSTALLER_SCRIPT}" WORKING_DIRECTORY "bin/Release")
	else()
		message(STATUS "Could not find NSIS, skipping installer")
	endif()

	# Docs
	find_program(DOXYGEN_PATH doxygen)
	if (DOXYGEN_PATH)
		message(STATUS "Will generate docs")
		file(GLOB DOX_SOURCES "YAP/include/*.hpp")
		add_custom_target(docs ALL ${DOXYGEN_PATH} DEPENDS ${DOX_SOURCES} DEPENDS ${DOX_SOURCES})
	else()
		message(WARNING "Could not find Doxygen, skipping docs")
	endif()
endif()

##### TESTS #####
if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows" OR wine_exec)
	# Build test executable
	add_executable(test_executable WIN32 tests/test.cpp)
	target_link_options(test_executable PUBLIC -mconsole)
	set_target_properties(test_executable PROPERTIES PREFIX "" SUFFIX ".exe")

	# Test function
	function(run_test yaproj)
	    add_test(NAME "Protect (easy) - ${yaproj}" COMMAND ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:YAPClient> ${PROJECT_SOURCE_DIR}/tests/${yaproj}.yaproj protect $<TARGET_FILE:test_executable> ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
	    if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
	        add_test(NAME "Run (easy) - ${yaproj}" COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe & del ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
	    endif()
		add_test(NAME "Protect (hard) - ${yaproj}" COMMAND ${CROSSCOMPILING_EMULATOR} $<TARGET_FILE:YAPClient> ${PROJECT_SOURCE_DIR}/tests/${yaproj}.yaproj protect $<TARGET_FILE:YAPClient> ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
		if (CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
	        add_test(NAME "Run (hard) - ${yaproj}" COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe --version & del ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/testing.exe)
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
	run_test(packer/all-release)
	run_test(packer/all)

	# Reassembler tests
	run_test(reasm/0)
	run_test(reasm/1)
	run_test(reasm/2)
	run_test(reasm/all)

	# Combo tests
	run_test(combo/packer-reasm/0)
	run_test(combo/packer-reasm/1)
	run_test(combo/packer-reasm/2)
	run_test(combo/packer-reasm/3)
	run_test(combo/packer-reasm/4)
	run_test(combo/packer-reasm/all)
	# run_test(combo/packer-reasm/partial_loading)
endif()
