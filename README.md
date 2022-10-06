
# DPHPC - Lightning McQueens

# Requirements
* OpenMP
* OpenMPI
* CMake
* gcc

# Building

```
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
