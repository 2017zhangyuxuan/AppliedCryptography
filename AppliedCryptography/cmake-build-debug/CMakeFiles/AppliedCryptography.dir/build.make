# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = "/Users/zhangyuxuan/Library/Application Support/JetBrains/Toolbox/apps/CLion/ch-0/212.5457.51/CLion.app/Contents/bin/cmake/mac/bin/cmake"

# The command to remove a file.
RM = "/Users/zhangyuxuan/Library/Application Support/JetBrains/Toolbox/apps/CLion/ch-0/212.5457.51/CLion.app/Contents/bin/cmake/mac/bin/cmake" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/AppliedCryptography.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/AppliedCryptography.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/AppliedCryptography.dir/flags.make

CMakeFiles/AppliedCryptography.dir/main.cpp.o: CMakeFiles/AppliedCryptography.dir/flags.make
CMakeFiles/AppliedCryptography.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/AppliedCryptography.dir/main.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AppliedCryptography.dir/main.cpp.o -c /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/main.cpp

CMakeFiles/AppliedCryptography.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AppliedCryptography.dir/main.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/main.cpp > CMakeFiles/AppliedCryptography.dir/main.cpp.i

CMakeFiles/AppliedCryptography.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AppliedCryptography.dir/main.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/main.cpp -o CMakeFiles/AppliedCryptography.dir/main.cpp.s

# Object files for target AppliedCryptography
AppliedCryptography_OBJECTS = \
"CMakeFiles/AppliedCryptography.dir/main.cpp.o"

# External object files for target AppliedCryptography
AppliedCryptography_EXTERNAL_OBJECTS =

../build/output/bin/AppliedCryptography: CMakeFiles/AppliedCryptography.dir/main.cpp.o
../build/output/bin/AppliedCryptography: CMakeFiles/AppliedCryptography.dir/build.make
../build/output/bin/AppliedCryptography: ../build/output/lib/libFIRSTWORK_LIB.a
../build/output/bin/AppliedCryptography: ../build/output/lib/libUTIL_LIB.a
../build/output/bin/AppliedCryptography: ../build/output/lib/libHASH_LIB.a
../build/output/bin/AppliedCryptography: CMakeFiles/AppliedCryptography.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../build/output/bin/AppliedCryptography"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/AppliedCryptography.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/AppliedCryptography.dir/build: ../build/output/bin/AppliedCryptography
.PHONY : CMakeFiles/AppliedCryptography.dir/build

CMakeFiles/AppliedCryptography.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/AppliedCryptography.dir/cmake_clean.cmake
.PHONY : CMakeFiles/AppliedCryptography.dir/clean

CMakeFiles/AppliedCryptography.dir/depend:
	cd /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug /Users/zhangyuxuan/WordAndStudy/ClionProjects/AppliedCryptography/cmake-build-debug/CMakeFiles/AppliedCryptography.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/AppliedCryptography.dir/depend
