#!/bin/bash

# sets some variables for developing
export PROOT=`pwd`
export SNITCH_ROOT=`pwd`/snitch
export SIM=$SNITCH_ROOT/hw/system/snitch_cluster/bin/snitch_cluster.vlt

# Used when building
export TOOLCHAIN_LLVM_FILE=$SNITCH_ROOT/sw/cmake/toolchain-llvm.cmake

# Commands
alias proot="cd $PROOT"
alias sim="$SIM"
alias run="banshee --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l"
alias build="cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE .. && cmake --build . -j"

