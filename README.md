
# DPHPC - Lightning McQueens

The goal of our project is to develop optimized operators from the ONNX standard for the snitch architecture.

# Requirements
* Either:
    * docker/podman
* or ("local")
    * bender
    * verilator (exactly version 4.200; 5.004 does not work for me)
    * riscv compiler
    * dependencies of `snitch/python-requirements.txt` and `snitch/apt-requirements.txt`
* cmake and gcc

# Setup - Development Environment

## Clone the snitch repo
Execute in the project root directory:
```bash
git submodule update --init
```

## Load aliases
After installing everthing you can source `env.sh` inside the **project root directory**:
```bash
source ./scripts/env.sh
```

This sets the following variables and aliases:
* `proot` to change the directory to the project root
* `dbuild` to build for banshee using **docker**
* `pbuild` to build for banshee using **podman**
* `build` to build for banshee locally
* `dbuild_size SIZE` to build for banshee using **docker** with given input size for the benchmark
* `pbuild_size SIZE` to build for banshee using **podman** with given input size for the benchmark
* `build_size SIZE` to build for banshee locally with given input size for the benchmark
* `build_sim` to build for the simulator locally
    * Run `clean` before switching from a banshee build and vice versa!
* `build_sim_size` to build for the simulator locally with given input size for the benchmark
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

## Install a riscv compiler
If you want to install the environment yourself and do not want to use docker. This allows you to use `build` and `build_size`.

First define `$RISCV` to point to the directory you want to have the toolchain installed to.

```
export RISCV=$HOME/.local/llvm-riscv

curl -Ls --progress-bar -o riscv-llvm.tar.gz https://sourceforge.net/projects/pulp-llvm-project/files/nightly/riscv32-pulp-llvm-ubuntu2004.tar.gz/download

tar -C $RISCV -xf riscv-llvm.tar.gz --strip-components=1

for file in riscv64-*; do ln -s $file $(echo "$file" | sed 's/^riscv64/riscv32/g'); done
```

## Building banshee
To build banshee you have to execute the following commands:
```bash
cd ./snitch/sw/banshee
cargo install --path .
```

# Building the project
* First run `source ./scripts/env.sh` if you have not done so already
* `dbuild` for docker (or `build`)
    * The build files should then be in `./build`

Now you can simulate the built applications with:
```
run ./build/hello_world
```

# Implemented
* SSR
    * abs, acos, acosh, add, argmax, asinh, batchnorm, conv, conv2d, copy, cumsum, div, dot, dropout, gemm, masked_dropout, max, maxpool, maxpool2d, relu, sigmoid, sin, sum, transpose, unique
* FREP
    * abs, add, batchnorm, conv, conv2d, copy, cumsum, div, dot, dropout, gemm, masked_dropout, max, maxpool, maxpool2d, relu, sigmoid, sin, sum, transpose
* Parallelised (w/o any helpers except barriers)
    * abs, add, argmax, conv, gemm, sin, sum
* OMP
    * add, add, gemm, sin, sum


# Running benchmarks and generating plots
Note: To use the python-benchmarker, you need banshee and python3 set up.

First install the python dependencies found in `plots/requirements.txt`. We recommend doing this in a virtual environment.
To set up the virtual python environment, run the following commands from the project root:
```bash
python3 -m venv plots/.venv
source ./plots/.venv/bin/activate
pip install -r plots/requirements.txt
```

To run the benchmarks for some specific operater (e.g. for the abs-operator), you can execute the following:
```bash
python3 plots/scraper.py -include abs
```
You can also specify up to which size we double (We start at 10 and double each run).
For example:
```bash
python3 plots/scraper.py -inclide abs -builder 'dbuild_size 40'
```
* This will build and run the sizes: `10, 20, 40`


This script builds the project using docker (or any other build command from above using, i.e: `-builder 'pbuild_size ZXY`), runs the benchmark using banshee and stores the measurements in a file for later use. Note that this might take a couple of minutes depending on the operator.
To view a runtime plot of the abs-operator which you have just benchmarked, run:
```bash
python3 plots/runtime_plot.py -include abs
```

If you want to exclude a plot line from the runtime plot, use the "-exclude" flag. For example: 
```bash
python3 plots/runtime_plot.py -include abs -exclude frep
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


# Report notes
* Publish repository and add link to it in the report
* increase core count is not possible as it freezes and has 'branch to unpredicted address' errors (in banshee)

# TODO
* plot some theoretical lower bounds
* calculate theoretical runtime
* colors/plotstyle consistent
* comparison of theoretical runtime of problem relative to runtime on x86
* look into bug of spilling
* look into bug of multiple SSR configurations
* parallelize
    * conv2d, maxpool, maxpool2d, transpose, max, unique
* scatter/gather
    * here we should not use powers of 2 (they are optimal for trees)
* rnn?

# DONE
* TEST core count configuration of SIMULATOR
* Use multiple cores
    * argmax
* conv parallel
* fix batchnorm benchmark
    * manually created as SSR is configured three times and this causes problems
* bar plot
* barrier wait indefinitely; reduce has "undefined symbol: __kmpc_reduce_nowait" compile error
* SSR+FREP
    * abs, acos (no frep), acosh (no frep), add, argmax (no frep), asinh (no frep), batchnorm, copy, cumsum, div, dot, dropout, gemm, masked_dropout, max, maxpool, relu, sigmoid, sin, sum, transpose
* Parallel
    * abs, add, copy, sin (no frep), sum, gemm
* OMP:
    * abs, add, copy, sin (no frep), sum (broken due to SSR 'leaking' or wrong impl.), gemm
* Use memory start pointer instead of l1?
    * Use start pointer; implemented in lmq.c
    * L1 has a better latency than memory
* should we do it for all datatypes (uint8, uint16, float32, ...)?
    * for `float` for now
* ask if we need to accept n dimensional input
    * Answer: Use vectors where possible
* Build for the simulator using a compile flag?
    * use `-DCLUSTER_SIM=1` when calling `cmake ..` or simply use the alias `build_sim`
* Have a command to output assembly
    * can be done if compiled as executable. sufficient?
* setup building
* Find project and TA
* Created repo
* Created scraper scripts that runs benchmarks and dumps their runtime into json files
* Created scripts for automatically generating runtime plots

