cmake_minimum_required(VERSION 3.13)

set(SNITCH_SOFTWARE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/sw/)
list(APPEND CMAKE_MODULE_PATH ${SNITCH_SOFTWARE_DIR}/cmake)
set(CMAKE_TOOLCHAIN_FILE toolchain-llvm CACHE STRING "Toolchain to use")

project(Benchmarks LANGUAGES C ASM)
include(SnitchUtilities)

add_compile_options(-O3 -g -ffunction-sections)

# Build the runtime
add_subdirectory(${SNITCH_SOFTWARE_DIR}snRuntime snRuntime)

# Compile the snitch benchmark (matrix multiplication)
include_directories(${SNITCH_SOFTWARE_DIR}benchmark/include)
include_directories(${SNRUNTIME_INCLUDE_DIRS})

add_library(benchmark ${SNITCH_SOFTWARE_DIR}benchmark/src/benchmark.c)

add_library(benchmark-matmul snitch/sw/benchmark/src/matmul/matmul.c snitch/sw/benchmark/src/matmul/data.S)
add_snitch_executable(benchmark-matmul-baseline snitch/sw/benchmark/src/matmul/main_baseline.c)
add_snitch_executable(benchmark-matmul-ssr snitch/sw/benchmark/src/matmul/main_ssr.c)
add_snitch_executable(benchmark-matmul-ssr_frep snitch/sw/benchmark/src/matmul/main_ssr_frep.c)
add_snitch_executable(benchmark-matmul-all snitch/sw/benchmark/src/matmul/main_all.c)

target_link_libraries(benchmark-matmul benchmark ${SNITCH_RUNTIME})
target_link_libraries(benchmark-matmul-baseline benchmark-matmul)
target_link_libraries(benchmark-matmul-ssr benchmark-matmul)
target_link_libraries(benchmark-matmul-ssr_frep benchmark-matmul)
target_link_libraries(benchmark-matmul-all benchmark-matmul)

# LMQ includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/onnx)

add_snitch_executable(hello_world ./src/hello_world/main.c)
add_snitch_executable(debug-multicore ./src/debug-multicore/main.c)

# Compile 'sum' library and its corresponding benchmark
add_library(summation src/onnx/sum_baseline_O0.c src/onnx/sum_baseline_O3.c)

set_source_files_properties(src/onnx/sum_baseline_O3.c PROPERTIES COMPILE_FLAGS -O3)
set_source_files_properties(src/onnx/sum_baseline_O0.c PROPERTIES COMPILE_FLAGS -O0)

add_snitch_executable(benchmark_sum ./src/benchmark/benchmark_sum.c)
target_link_libraries(benchmark_sum summation)


