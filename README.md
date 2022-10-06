
# DPHPC - Lightning McQueens

# Requirements
* Currently none (TODO: Add OpenMP and OpenMPI - if needed - to build process)

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

# DONE
    * Link and build with OpenMP
    * Link and build liblsb
    * Link and build with OpenMPI
    * Created repo
