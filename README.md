
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

## Load aliases
After installing everthing you can source env.sh inside the **project root directory**: 
```
source ./scripts/env.sh
```

This sets the following variables and aliases:
* `proot` to switch to the project root
* `dbuild` to build using **docker**
* `pbuild` to build using **podman**
* `build` to build locally
* `run` to run using banshee (which must be on your *PATH*)

## Building the simulator
 * Only if you are not using `banshee`
Make sure to not forget [sourcing env.sh](#load-aliases).

This needs only to be done once:

```
cd snitch/hw/system/snitch_cluster/
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
* First run `source ./scripts/env.sh`
* `dbuild` for docker
    * The build files should then be in `./build`

Now you can simulate the built applications with:
```
run ./build/hello_world
```

# Used Libraries
* [snitch](https://github.com/pulp-platform/snitch.git)


# Running on EULER
* Maybe?

# TODO
* banshee
* Have a command to output assembly
    * can be done if compiled as executable. sufficient?
* ask if we need to accept n dimensional input
* should we do it for all datatypes (uint8, uint16, float32, ...)?
* 

# DONE
* setup building
* Find project and TA
* Created repo
