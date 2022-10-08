
# DPHPC - Lightning McQueens

The goal of our project TODO.

# Requirements
* OpenMP
* OpenMPI
* CMake
* gcc

# Development Environment
```bash
source ./scripts/env.sh
```
This makes the following aliases available:
* `run`: Compiles and runs with MPI
* `raw_run`: Compiles and runs **without** MPI (used for development of single parts)
* `bm_run`: Compiles as runs **with** MPI and LSB to measure the performance
* `euler_init`: Loads all necessary modules on EULER

* [Here may be added more aliases to run our application or do other stuff] 


# Building

```bash
cd build/
cmake ..
cmake --build .
./main
```
or simply `cd build/ && cmake .. && cmake --build . && mpirun -n X ./main`

# Used Libraries
* [LibSciBench](https://spcl.inf.ethz.ch/Research/Performance/LibLSB/)
    * For performance measurements

# TODO
    * Find a task
    * Email to TA for approval

# Project on some graph algorithm
    * Generating graphs
        * Do we also parallelize the generation of a graph?
        * We need to generate different types of graphs!
        * In which format are they generated?
            * Such that we can store them on disk and not have to regenerate them every run
        * Graph generation: [anu.edu](http://users.cecs.anu.edu.au/~bdm/plantri/)
    * Serial implementation
        * Create a baseline (duration for given problems; confidence interval)
        * Verify correctness? Store result in some format to have a comparison for the results of the parallel algorithms
    * Multiple parallel implementations
        * compare with serial results
    * How do we verify that the output is correct (algorithm has guarantee of O(...))
        * Parallel verification?


# DONE
    * Link and build with OpenMP
    * Link and build liblsb
    * Link and build with OpenMPI
    * Created repo
