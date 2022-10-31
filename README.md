
# DPHPC - Lightning McQueens

The goal of our project is to develop optimized operators (from the ONNX standard) for the snitch architecture.

# Requirements
* Either:
    * docker/podman
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
* `proot` to change the directory to the project root
* `dbuild` to build for banshee using **docker**
* `pbuild` to build for banshee using **podman**
* `build` to build for banshee locally
* `build_cluster` to build for the simulator locally
    * Run `clean` before switching from a banshee build and vice versa!
* `clean` to remove all temporary build files
* `run` to run using banshee (which must be on your *PATH*)
* `bench` to run **all** benchmarks (all binaries inside build/ that start with `benchmark_`)

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

# Helpful Links
* [gcc inline assembly](https://www.felixcloutier.com/documents/gcc-asm.html)
* [onnx operators](https://github.com/onnx/onnx/blob/main/docs/Operators.md#aionnx-default)
* [llvm fork](https://github.com/pulp-platform/llvm-project#ssr)
* [ssr papter](https://arxiv.org/pdf/1911.08356.pdf)
* [snitch paper](https://arxiv.org/pdf/2002.10143.pdf )
* [snitch getting started](https://pulp-platform.github.io/snitch/ug/getting_started/)
* [RISCV registers](https://en.wikichip.org/wiki/risc-v/registers)
* [RISCV spec](https://github.com/riscv/riscv-isa-manual/releases/download/Ratified-IMAFDQC/riscv-spec-20191213.pdf)
* [Register saves](https://web.eecs.utk.edu/~smarz1/courses/ece356/notes/assembly/)


# Running on EULER
* Maybe?

# TODO
* banshee build script?
* Use memory start pointer instead of l1?
* File where we store the benchmark results (to plot later in the report)

# DONE
* should we do it for all datatypes (uint8, uint16, float32, ...)?
    * for `float` for now
* ask if we need to accept n dimensional input
    * Answer: Use vectors where possible
* Build for the simulator using a compile flag?
    * use `-DCLUSTER_SIM=1` when calling `cmake ..` or simply use the alias `build_cluster`
* Have a command to output assembly
    * can be done if compiled as executable. sufficient?
* setup building
* Find project and TA
* Created repo
