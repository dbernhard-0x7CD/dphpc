cmake_minimum_required(VERSION 3.13)

set(SNITCH_SOFTWARE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/sw/)
list(APPEND CMAKE_MODULE_PATH ${SNITCH_SOFTWARE_DIR}/cmake)
set(CMAKE_TOOLCHAIN_FILE toolchain-llvm CACHE STRING "Toolchain to use")

project(snitch-onnx LANGUAGES C ASM)
if (CLUSTER_SIM)
    message("Linking against snRuntime-cluster. Use snitch_cluster.vlt to simulate")
    set(SNITCH_SIMULATOR ${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snitch_cluster/bin/snitch_cluster.vlt CACHE PATH "")
    set(TARGET_LINKER_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/snitch/hw/system/snitch_cluster/generated/link.ld CACHE PATH "")
    set(SNITCH_RUNTIME snRuntime-cluster CACHE STRING "")
else()
    message("Using banshee. Use banshee BINARY to simulate. (f.ex: --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l")
    set(SNITCH_RUNTIME snRuntime-banshee CACHE STRING "")
endif()

include(SnitchUtilities)

add_compile_options(-O3 -g -ffunction-sections)

# Build the runtime
add_subdirectory(${SNITCH_SOFTWARE_DIR}snRuntime snRuntime)
add_subdirectory(${SNITCH_SOFTWARE_DIR}benchmark benchmark)


include_directories(${SNRUNTIME_INCLUDE_DIRS})

# LMQ includes
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/onnx)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/benchmark)


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

# Compile 'div'
add_library(div src/onnx/div.c)
add_snitch_executable(benchmark_div ./src/benchmark/benchmark_div.c)
target_link_libraries(benchmark_div div)

# Compile 'abs'
add_library(abs src/onnx/abs.c)
add_snitch_executable(benchmark_abs ./src/benchmark/benchmark_abs.c)
target_link_libraries(benchmark_abs abs)

#Compile 'copy'
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/copy)
add_library(copy src/copy/copy.c)
add_snitch_executable(benchmark_copy ./src/benchmark/benchmark_copy.c)
target_link_libraries(benchmark_copy copy)

# Compile 'relu'
add_library(relu src/onnx/relu.c)
add_snitch_executable(benchmark_relu ./src/benchmark/benchmark_relu.c)
target_link_libraries(benchmark_relu relu)

# Compile 'scatter'
add_library(scatter src/onnx/scatter.c)
add_snitch_executable(benchmark_scatter ./src/benchmark/benchmark_scatter.c)
target_link_libraries(benchmark_scatter scatter)