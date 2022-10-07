#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <omp.h>

#include <ostream>
#include <iostream>

#include "main.hpp"

// comment out to disable LSB
// #define USE_LSB

// comment out to disable MPI
// #define USE_MPI

#ifdef USE_LSB
#include <liblsb.h>
#endif

#define ITERATION_N 10

int main(int argc, char** argv) {
    
    cout << "Build configuration:\n";
#ifdef USE_MPI
    cout << "\t Using MPI" << std::endl;
#endif
#ifdef USE_LSB
    cout << "\t Using MPI" << std::endl;
#endif

    cout << "End build configuration" << std::endl;

#ifdef USE_MPI
    MPI_Init(&argc, &argv);
#endif

#ifdef USE_LSB
    LSB_Init("test_reduce", 0);
#endif

    omp_reduction();
    // mpi_reduction();

    
#ifdef USE_LSB
    LSB_Finalize();
#endif

#ifdef USE_MPI
    MPI_Finalize();
#endif
}

void mpi_reduction() {
    int rank, size;

    // simply sums all ranks to the root
    int sum = 0;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

#ifdef USE_LSB
    LSB_Set_Rparam_int("rank", rank);
    LSB_Set_Rparam_int("runs", 1);
#endif
    
    int myValue = rank + 1;
    
    if (rank == 0) {
        std::cout << "Starting main" << std::endl;
    }

    //warmup
    MPI_Reduce(&myValue, &sum, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);
    
    for (int i = 0; i < ITERATION_N; i++) {
        sum = 0;
#ifdef USE_LSB
        LSB_Res();
#endif

        MPI_Reduce(&myValue, &sum, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

#ifdef USE_LSB
        LSB_Rec(1);
#endif
    }

    if (rank == 0) {
        std::cout << "Sum from 1 to " << size << " is " << sum << std::endl; 
        std::cout << "Finished" << std::endl;
    }
}

void omp_reduction() {
    std::cout << "starting" << std::endl;

    int sum = 0;

#pragma omp parallel reduction(+: sum)
    sum = omp_get_thread_num() + 1;

    std::cout << "Sum is " << sum << std::endl;
}
