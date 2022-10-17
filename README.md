
# DPHPC - Lightning McQueens

The goal of our project is to develop optimized operators (from the ONNX standard) for the snitch architecture.

# Requirements
* Either:
    * docker
* or ("local")
    * bender
    * verilator
    * riscv compiler
    * dependencies of `snitch/python-requirements.txt` and `snitch/apt-requirements.txt`

# Setup - Development Environment

First we need to clone the snitch repo:
```
git submodule update --init
```

After installing everthing you can souce env.sh: `source ./scripts/env.sh` (This must be done in the project root).

This sets the following variables and aliases:
* `sim` to simulate an application for the snitch
* ``

## docker - Once

Only needed if developing with docker.
Run this in the root of the project folder:
```
docker run -it -v `pwd`:/repo -w /repo ghcr.io/pulp-platform/snitch
```

Creates a new docker container with this project mounted at `/repo`.

**Afterwards** you can run `docker exec -it CONTAINER_NAME /bin/bash` to restart the container.

### Building the simulator
```
cd snich/hw/system/snitch_cluster/
make bin/snitch_cluster.vlt
```

## Install riscv compiler (if you install the environment yourself)

First define `$RISCV` to point to the directory you want to have the toolchain installed to.

```
curl -Ls -o riscv-gcc.tar.gz https://static.dev.sifive.com/dev-tools/riscv64-unknown-elf-gcc-8.3.0-2020.04.0-x86_64-linux-ubuntu14.tar.gz

tar -C $RISCV -xf riscv-gcc.tar.gz --strip-components=1

for file in riscv64-*; do ln -s $file $(echo "$file" | sed 's/^riscv64/riscv32/g'); done
```

# Building

```
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_LLVM_FILE ../
```

Now you can simulate the built applications with:
```
sim ./hello_world
```

# Used Libraries


# Running on EULER
* Maybe?

# TODO
* setup building

# DONE
* Find project and TA
* Created repo
