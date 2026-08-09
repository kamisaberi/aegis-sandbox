# CMakeLists.txt
# Root C++20 & eBPF Build System for aegis-sandbox
# Author: Kamran Saberifard
# License: Apache 2.0

cmake_minimum_required(VERSION 3.20)

project(aegis-sandbox
    VERSION 0.1.0
    DESCRIPTION "Sub-10ms MicroVM & eBPF Isolation Engine for AI Agents"
    LANGUAGES C CXX
)

# ------------------------------------------------------------------------------
# 1. C++ Standard & Compiler Flags
# ------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Default to Debug build type for development and testing
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wnon-virtual-dtor
    -Wold-style-cast
    -Wnull-dereference
    -Wconversion
)

# ------------------------------------------------------------------------------
# 2. Find Dependencies (libbpf, libelf, bpftool, Threads)
# ------------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Check for libbpf
pkg_check_modules(LIBBPF REQUIRED libbpf)
message(STATUS "[aegis-sandbox] Found libbpf: Version ${LIBBPF_VERSION}")

# Check for libelf (required by libbpf)
pkg_check_modules(LIBELF REQUIRED libelf)

# Check for bpftool executable
find_program(BPFTOOL_EXECUTABLE NAMES bpftool)
if(NOT BPFTOOL_EXECUTABLE)
    message(WARNING "[aegis-sandbox] bpftool not found! vmlinux.h generation will be skipped.")
else()
    message(STATUS "[aegis-sandbox] Found bpftool: ${BPFTOOL_EXECUTABLE}")
endif()

# ------------------------------------------------------------------------------
# 3. eBPF Bytecode Target Compilation (clang -target bpf)
# ------------------------------------------------------------------------------
set(EBPF_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ebpf)
set(EBPF_OUTPUT_DIR ${CMAKE_BINARY_DIR}/ebpf_obj)
file(MAKE_DIRECTORY ${EBPF_OUTPUT_DIR})

set(EBPF_SOURCES
    ${EBPF_SOURCE_DIR}/sys_filter.bpf.c
    ${EBPF_SOURCE_DIR}/net_filter.bpf.c
    ${EBPF_SOURCE_DIR}/process_monitor.bpf.c
)

set(EBPF_OBJECTS "")

foreach(EBPF_SRC ${EBPF_SOURCES})
    get_filename_component(EBPF_NAME ${EBPF_SRC} NAME_WE)
    set(EBPF_OBJ ${EBPF_OUTPUT_DIR}/${EBPF_NAME}.bpf.o)
    
    add_custom_command(
        OUTPUT ${EBPF_OBJ}
        COMMAND clang -O2 -target bpf -g 
                -D__TARGET_ARCH_x86
                -I${EBPF_SOURCE_DIR}/include
                -I${LIBBPF_INCLUDE_DIRS}
                -c ${EBPF_SRC} -o ${EBPF_OBJ}
        DEPENDS ${EBPF_SRC}
        COMMENT "[eBPF Compiler] Building BPF bytecode object: ${EBPF_NAME}.bpf.o"
    )
    
    list(APPEND EBPF_OBJECTS ${EBPF_OBJ})
endforeach()

add_custom_target(aegis_ebpf_bytecode DEPENDS ${EBPF_OBJECTS})

# ------------------------------------------------------------------------------
# 4. Core C++ Native Runtime Library (`aegis_core`)
# ------------------------------------------------------------------------------
file(GLOB_RECURSE AEGIS_CXX_SOURCES
    "src/*.cpp"
)

add_library(aegis_core SHARED ${AEGIS_CXX_SOURCES})
add_dependencies(aegis_core aegis_ebpf_bytecode)

target_include_directories(aegis_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        ${LIBBPF_INCLUDE_DIRS}
        ${LIBELF_INCLUDE_DIRS}
)

target_link_libraries(aegis_core
    PUBLIC
        ${LIBBPF_LIBRARIES}
        ${LIBELF_LIBRARIES}
        Threads::Threads
)

# ------------------------------------------------------------------------------
# 5. CLI Executable (`aegis-cli`)
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmd/aegis-cli/main.cpp")
    add_executable(aegis-cli cmd/aegis-cli/main.cpp)
    target_link_libraries(aegis-cli PRIVATE aegis_core)
endif()

# ------------------------------------------------------------------------------
# 6. Unit & Integration Tests
# ------------------------------------------------------------------------------
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    enable_testing()
    add_subdirectory(tests)
endif()