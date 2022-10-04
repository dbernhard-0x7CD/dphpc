cmake_minimum_required(VERSION 3.10)

project(dphpc-working-title VERSION 0.1)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Libraries
find_package(MPI REQUIRED)
find_package(OpenMP REQUIRED)

# Build LibSciBench
# Used to build liblsb
include(ExternalProject)

ExternalProject_Add(liblsb
  GIT_REPOSITORY https://github.com/spcl/liblsb.git
  SOURCE_DIR liblsb
  BUILD_IN_SOURCE True
  UPDATE_COMMAND ""
  INSTALL_DIR "${CMAKE_BINARY_DIR}/install"
  INSTALL_COMMAND "make" "install"
  CONFIGURE_COMMAND "autoreconf" "-f" "-i" && "./configure" "--prefix=${CMAKE_BINARY_DIR}/install"
  BUILD_COMMAND "make"
)

# For the headers
include_directories(${CMAKE_BINARY_DIR}/liblsb/)
include_directories(${MPI_INCLUDE_PATH})

set(SOURCE_FILES, src/main.cpp)

add_executable(main src/main.cpp)

target_link_libraries(main ${MPI_LIBRARIES} ${CMAKE_BINARY_DIR}/install/lib/liblsb.a OpenMP::OpenMP_CXX)

if(MPI_COMPILE_FLAGS)
  set_target_properties(main PROPERTIES COMPILE_FLAGS "${MPI_COMPILE_FLAGS}")
endif()

if(MPI_LINK_FLAGS)
  set_target_properties(main PROPERTIES LINK_FLAGS "${MPI_LINK_FLAGS}")
endif()

