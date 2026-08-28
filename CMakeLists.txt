cmake_minimum_required(VERSION 3.28)
project(jocky VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Try LLVM (optional - fallback to textual IR if not found)
find_package(LLVM QUIET CONFIG)
if(LLVM_FOUND)
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  add_definitions(${LLVM_DEFINITIONS})
  include_directories(${LLVM_INCLUDE_DIRS})
else()
  message(STATUS "LLVM not found - using textual IR fallback (no link needed)")
endif()

# ANTLR runtime (optional)
find_path(ANTLR_INCLUDE antlr4-runtime.h PATH_SUFFIXES antlr4-runtime)
find_library(ANTLR_LIB antlr4-runtime)

add_subdirectory(jocky)
add_subdirectory(agent)
add_subdirectory(runtime)
