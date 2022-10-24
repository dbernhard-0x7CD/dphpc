cmake_minimum_required(VERSION 3.13)

set(SNITCH_SOFTWARE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/sw/)
list(APPEND CMAKE_MODULE_PATH ${SNITCH_SOFTWARE_DIR}/cmake)
set(CMAKE_TOOLCHAIN_FILE toolchain-llvm CACHE STRING "Toolchain to use")

project(Benchmarks LANGUAGES C ASM)
include(SnitchUtilities)

add_compile_options(-O3 -g -ffunction-sections)

# Build the runtime
add_subdirectory(${SNITCH_SOFTWARE_DIR}snRuntime snRuntime)
add_subdirectory(${SNITCH_SOFTWARE_DIR}benchmark benchmark)


include_directories(${SNRUNTIME_INCLUDE_DIRS})

# LMQ includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/onnx)

add_snitch_executable(hello_world ./src/hello_world/main.c)
add_snitch_executable(debug-multicore ./src/debug-multicore/main.c)

# Compile 'sum' library and its corresponding benchmark
add_library(summation src/onnx/sum.c)

add_snitch_executable(benchmark_sum ./src/benchmark/benchmark_sum.c)
target_link_libraries(benchmark_sum summation)

# Compile 'add'
add_library(add src/onnx/add.c)
add_snitch_executable(benchmark_add ./src/benchmark/benchmark_add.c)
target_link_libraries(benchmark_add add)

#Compile 'copy'
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/copy)
add_library(copy src/copy/copy.c)
add_snitch_executable(benchmark_copy ./src/benchmark/benchmark_copy.c)
target_link_libraries(benchmark_copy copy)
