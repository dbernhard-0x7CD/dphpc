#!/bin/bash

# sets some important variables for developing

export PROOT=`pwd`/

# Only allow if we're in the project root
# NOTE: actually you could be in the project root with ../PROJ_ROOT/scripts/env.sh but this is not supported
# if [[ $0 != ./scripts/env.sh ]]
# then
#     echo "Source must be done in the project root. I'm the executable at $0"
#     # return 0
# fi

echo "Setting aliases and variables"

export SNITCH_ROOT=`pwd`/snitch
export SIM=$SNITCH_ROOT/hw/system/snitch_cluster/bin/snitch_cluster.vlt

# Used when building
export TOOLCHAIN_LLVM_FILE=$SNITCH_ROOT/sw/cmake/toolchain-llvm.cmake

###### Commands

# Change to the project root directory

# NOT SUPPORTED
# function sim () {"$SIM"}

# Runs using banshee and the default configuration
function run () { 
    banshee --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l $1
    }

# Builds using docker
function dbuild () { 
    docker run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build 
    }

# Builds using docker for given input size
function dbuild_size () {
    docker run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build $1 $2
}

# # Remove all built files
# function clean () {
#     rm -r "$PROOT"build/*
# }

# function bench () {
#     echo $bench_cmd | bash 2>&1
# }

echo ---RUNNING COMPILER---
dbuild_size $1 >/dev/null

echo ---RUNNING SIMULATOR---
echo benching $2
run $2
echo ---SIMULATOR DONE---
