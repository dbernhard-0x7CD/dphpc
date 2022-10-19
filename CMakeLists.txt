cmake_minimum_required(VERSION 3.13)

set(SNITCH_SOFTWARE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/sw/)

list(APPEND CMAKE_MODULE_PATH ${SNITCH_SOFTWARE_DIR}/cmake)

set(SNITCH_RUNTIME snRuntime-cluster CACHE STRING "")
set(SNITCH_SIMULATOR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snitch_cluster/bin/snitch_cluster.vlt CACHE PATH "")

set(TARGET_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snicth_cluster/generated/link.ld" CACHE PATH "")

project(snitch_cluster LANGUAGES C ASM)
include(SnitchUtilities)

# By default we compile with no compiler optimizations. TODO: State this in the report.
add_compile_options(-O0 -g -ffunction-sections)

# enable_testing()
add_subdirectory(${SNITCH_SOFTWARE_DIR}/snRuntime snRuntime)
add_subdirectory(${SNITCH_SOFTWARE_DIR}/snBLAS snBLAS)
add_subdirectory(${SNITCH_SOFTWARE_DIR}/benchmark benchmark)

include_directories(${SNRUNTIME_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/onnx)

add_snitch_executable(hello_world ./src/hello_world/main.c)
add_snitch_executable(debug-multicore ./src/debug-multicore/main.c)

# Compile 'sum' library and its corresponding benchmark
add_library(summation src/onnx/sum_baseline.c src/onnx/sum_baseline_O3.c)

# Add compile parameters for O3 optimization
set_source_files_properties(src/onnx/sum_baseline_O3.c PROPERTIES COMPILE_FLAGS -O3)

add_snitch_executable(benchmark_sum ./src/benchmark/benchmark_sum.c)
target_link_libraries(benchmark_sum summation)


