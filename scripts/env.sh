#!/bin/bash

# sets some important variables for developing

export PROOT=`pwd`/

# Only allow if we're in the project root
# NOTE: actually you could be in the project root with ../PROJ_ROOT/scripts/env.sh but this is not supported
if [[ $0 != ./scripts/env.sh ]]
then
    echo "Source must be done in the project root"
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
alias run='banshee --configuration $SNITCH_ROOT/sw/banshee/config/snitch_cluster.yaml -l'

# Builds locally
alias build='cd $PROOT/build && cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE .. && cmake --build . -j'

# Builds using docker
alias dbuild='docker run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build'

# Builds using podman
alias pbuild='podman run --rm -v $PROOT:/repo -w /repo --name snitch_build ghcr.io/pulp-platform/snitch /bin/bash ./container_build.sh build'

alias clean='rm -r "$PROOT"build/*'
