#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>

#include <ostream>
#include <iostream>

// :( This is nowhere documented that we need to set HAVE_MPI_H
// Does not compile without as else MPI_Comm is an alias to void*
#define HAVE_MPI_H
#include <liblsb.h>

int main(int argc, char** argv) {
    MPI_Init(&argc, &argv);

    int rank, size;

    // simply sums all ranks to the root
    int sum = 0;

    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    int myValue = rank + 1;
    
    if (rank == 0) {
        std::cout << "Starting" << std::endl;
    }

    MPI_Reduce(&myValue, &sum, 1, MPI_INT, MPI_SUM, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        std::cout << "Sum from 1 to " << size << " is " << sum << std::endl; 
        std::cout << "Finished" << std::endl;
    }
    
    MPI_Finalize();
}