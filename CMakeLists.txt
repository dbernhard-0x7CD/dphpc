cmake_minimum_required(VERSION 3.13)

set(SNITCH_SOFTWARE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/sw/)

list(APPEND CMAKE_MODULE_PATH ${SNITCH_SOFTWARE_DIR}/cmake)

set(SNITCH_RUNTIME snRuntime-cluster CACHE STRING "")
set(SNITCH_SIMULATOR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snitch_cluster/bin/snitch_cluster.vlt CACHE PATH "")

set(TARGET_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snicth_cluster/generated/link.ld" CACHE PATH "")

project(snitch_cluster LANGUAGES C ASM)
include(SnitchUtilities)

add_compile_options(-O3 -g -ffunction-sections)

# enable_testing()
add_subdirectory(${SNITCH_SOFTWARE_DIR}/snRuntime snRuntime)
add_subdirectory(${SNITCH_SOFTWARE_DIR}/snBLAS snBLAS)
add_subdirectory(${SNITCH_SOFTWARE_DIR}/benchmark benchmark)

include_directories(${SNRUNTIME_INCLUDE_DIRS})

add_snitch_executable(hello_world ./src/hello_world/main.c)
