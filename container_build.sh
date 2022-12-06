# First argument is the build directory
# Second argument (optional) the size of the inputs for the benchmarks

cd $1 && cmake .. -DCMAKE_TOOLCHAIN_FILE=toolchain-llvm -DLMQ_SIZE=$2 && cmake --build . -j