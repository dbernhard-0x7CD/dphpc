#!/bin/bash

# sets some important variables for developing

export PROOT=`pwd`/

# Only allow if we're in the project root
if [ ! -f "`pwd`/scripts/env.sh" ]; then
    echo "Source must be done in the project root. I'm the executable at `pwd`"
    return 0
fi

echo "Setting aliases and variables"

export SNITCH_ROOT=`pwd`/snitch
export SIM=$SNITCH_ROOT/hw/system/snitch_cluster/bin/snitch_cluster.vlt

# Used when building
export TOOLCHAIN_LLVM_FILE=$SNITCH_ROOT/sw/cmake/toolchain-llvm.cmake

###### Commands

# Change to the project root directory
alias proot='cd $PROOT'

# NOT SUPPORTED
alias sim="$SIM"

# Runs using banshee and the default configuration
run() {
    banshee --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l $1
}
export -f run

# Builds locally
build() {
    cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE .. && cmake --build . -j && cd ..
}
export -f build

# Builds against the vlt simulator (clean before running this)
build_sim() {
    cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE -DCLUSTER_SIM=1 .. && cmake --build . -j && cd ..
}
export -f build_sim

# Builds against the vlt simulator (clean before running this) with a given size for the benchmark
build_sim_size() {
    cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE -DCLUSTER_SIM=1 -DLMQ_SIZE=$1 .. && cmake --build . -j && cd ..
}
export -f build_sim_size

# Builds using docker
dbuild() {
    docker run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build
}
export -f dbuild

# Builds using podman
pbuild() {
    podman run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build
}
export -f pbuild

# Builds locally for given input size
build_size() {
    cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE -DLMQ_SIZE=$1 .. && cmake --build . -j && cd ..
}
export -f build_size

# Builds using docker for given input size
dbuild_size() {
    docker run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build $1 && cd build
}
export -f dbuild_size

# Builds using podman for given input size
pbuild_size() {
    podman run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build $1 && cd build
}
export -f pbuild_size

# Remove all built files
alias clean='rm -r "$PROOT"build/*'

# Runns all benchmarks (binary must start with benchmark_ and lie in the builds/ directory)
bench() {
    for x in $PROOT/build/benchmark_*;
    do
        if [[ $x != *.s ]]; then
            echo "Running $x"
            banshee --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l $x
        fi
    done
}

bench_sim() {
    for x in $PROOT/build/benchmark_*;
    do
        if [[ $x != *.s ]]; then
            echo "Running $x"
            $SIM $x
        fi
    done
}
