cmake_minimum_required(VERSION 3.10)

project(dphpc-working-title VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(MPI REQUIRED)

include_directories(liblsb/liblsb-0.2.2)
include_directories(${MPI_INCLUDE_PATH})

set(SOURCE_FILES, src/main.cpp)

add_executable(main src/main.cpp)
target_link_libraries(main ${MPI_LIBRARIES})

if(MPI_COMPILE_FLAGS)
  set_target_properties(main PROPERTIES COMPILE_FLAGS "${MPI_COMPILE_FLAGS}")
endif()

if(MPI_LINK_FLAGS)
  set_target_properties(main PROPERTIES LINK_FLAGS "${MPI_LINK_FLAGS}")
endif()

