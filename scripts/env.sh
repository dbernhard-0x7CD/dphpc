#!/bin/bash

# sets some important variables for developing

export SNITCH_ROOT=`pwd`/snitch
export SIM=$SNITCH_ROOT/hw/system/snitch_cluster/bin/snitch_cluster.vlt

# Used when building
export TOOLCHAIN_LLVM_FILE=$SNITCH_ROOT/sw/cmake/toolchain-llvm.cmake

# Commands
alias sim="$SIM"

