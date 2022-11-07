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
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/lmq)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/onnx)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/dot)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/benchmark)

add_snitch_executable(hello_world
                      ./src/lmq/lmq.c
                      ./src/hello_world/main.c)
add_snitch_executable(debug-multicore ./src/debug-multicore/main.c)

# Compile 'sum' library and its corresponding benchmark
add_library(summation src/onnx/sum.c)
add_snitch_executable(benchmark_sum
                      ./src/benchmark/benchmark_sum.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_sum summation)

# Compile 'add'
add_library(add src/onnx/add.c)
add_snitch_executable(benchmark_add
                      ./src/benchmark/benchmark_add.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_add add)

# Compile 'div'
add_library(div src/onnx/div.c)
add_snitch_executable(benchmark_div
                      ./src/benchmark/benchmark_div.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_div div)

# Compile 'abs'
add_library(abs src/onnx/abs.c)
add_snitch_executable(benchmark_abs
                      ./src/benchmark/benchmark_abs.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_abs abs)

#Compile 'copy'
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/copy)
add_library(copy src/copy/copy.c)
add_snitch_executable(benchmark_copy
                      ./src/benchmark/benchmark_copy.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_copy copy)

# Compile 'relu'
add_library(relu src/onnx/relu.c)
add_snitch_executable(benchmark_relu
                      ./src/lmq/lmq.c
                      ./src/benchmark/benchmark_relu.c)
target_link_libraries(benchmark_relu relu)

# Compile 'acos'
add_library(acos src/onnx/acos.c)
add_snitch_executable(benchmark_acos
                      ./src/benchmark/benchmark_acos.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_acos acos)

# Compile 'acosh'
add_library(acosh src/onnx/acosh.c)
add_snitch_executable(benchmark_acosh
                      ./src/benchmark/benchmark_acosh.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_acosh acosh)

# Compile 'sigmoid'
add_library(sigmoid src/onnx/sigmoid.c)
add_snitch_executable(benchmark_sigmoid
                      ./src/benchmark/benchmark_sigmoid.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_sigmoid sigmoid)

# Compile 'argmax'
add_library(argmax src/onnx/argmax.c)
add_snitch_executable(benchmark_argmax
                      ./src/benchmark/benchmark_argmax.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_argmax argmax)

# Compile 'max'
add_library(max src/onnx/max.c)
add_snitch_executable(benchmark_max
                      ./src/benchmark/benchmark_max.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_max max)

# Compile 'batchnorm'
add_library(batchnorm src/onnx/batchnorm.c)
add_snitch_executable(benchmark_batchnorm
                      ./src/benchmark/benchmark_batchnorm.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_batchnorm batchnorm)

# Compile 'cumsum'
add_library(cumsum src/onnx/cumsum.c)
add_snitch_executable(benchmark_cumsum
                      ./src/benchmark/benchmark_cumsum.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_cumsum cumsum)

# Compile 'dropout'
add_library(dropout src/onnx/dropout.c)
add_snitch_executable(benchmark_dropout
                      ./src/benchmark/benchmark_dropout.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_dropout dropout)

# Compile 'masked_dropout'
add_library(masked_dropout src/onnx/masked_dropout.c)
add_snitch_executable(benchmark_masked_dropout
                      ./src/benchmark/benchmark_masked_dropout.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_masked_dropout masked_dropout)

# Compile 'dot'
add_library(dot src/dot/dot.c)
add_snitch_executable(benchmark_dot
                      ./src/benchmark/benchmark_dot.c
                      ./src/lmq/lmq.c)
target_link_libraries(benchmark_dot dot)

# Compile 'sin'
add_library(sin src/onnx/sin.c)
add_snitch_executable(benchmark_sin ./src/benchmark/benchmark_sin.c)
target_link_libraries(benchmark_sin sin)