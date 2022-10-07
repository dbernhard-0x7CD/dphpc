# Builds without MPI or LSB
alias raw_run='''sh -c "cd build/ && 
    cmake -DUSE_MPI=0 .. &&
    cmake --build . -- &&
    ./main"'''

# Builds with MPI
alias run='''sh -c "cd build/ && 
    cmake -DUSE_MPI=1 .. &&
    cmake --build . -- &&
    ./main"'''