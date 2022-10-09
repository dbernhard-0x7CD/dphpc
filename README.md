
# DPHPC - Lightning McQueens

The goal of our project TODO.

# Requirements
* OpenMP
* OpenMPI
* CMake
* gcc
* boost library
* graphviz for rendering graphs

# Development Environment
You can load the aliases using:

```bash
source ./scripts/env.sh
```

This makes the following aliases available:
* `build`: Builds with MPI
* `raw_build`: Buildss **without** MPI (used for development of single parts)
* `bm_build`: Builds **with** MPI and LSB to measure the performance
* `run`: Builds and runs with MPI
* `raw_run`: Builds and runs **without** MPI (used for development of single parts)
* `bm_run`: Builds and runs **with** MPI and LSB to measure the performance
* `euler_init`: Loads all necessary modules on EULER

* [Here may be added more aliases to run our application or do other stuff] 


# Building

Use the aliases from the development environment or alernatively:

```bash
cd build/
cmake ..
cmake --build .
```

**Running**:
```bash
mpirun -n 10 build./main
```

or simply `cd build/ && cmake .. && cmake --build . && mpirun -n X ./main`

# Used Libraries
* [LibSciBench](https://spcl.inf.ethz.ch/Research/Performance/LibLSB/)
    * For performance measurements
* [boost](https://www.boost.org/)

* Maybe: 
    * https://arma.sourceforge.net/docs.html#Mat
    * https://github.com/DrTimothyAldenDavis/GraphBLAS
    * OpenMP alternative: https://cilk.mit.edu/

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
    * Link and build with boost
    * Link and build with OpenMP
    * Link and build liblsb
    * Link and build with OpenMPI
    * Created repo
