cmake_minimum_required(VERSION 3.10)

project(dphpc-working-title VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(liblsb/liblsb-0.2.2)
set(SOURCE_FILES, src/main.cpp)

add_executable(main src/main.cpp)

