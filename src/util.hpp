#ifndef LMQ_UTILS_H
#define LMQ_UTILS_H


#include <iostream>
#include <string.h>
#include <vector>

#include "main.hpp"

using namespace std;

/*
 * Loads a file with edges in the form "X Y" per line into a vector of Edges.
 * X,Y must fit into an unsigned long.
 * 
 * Returns: vector of edges
 * WHY: To load edges from a library which generates graphs.
 * NOTE: This may not be fully optimized
 */
vector<Edge> load_from_adjacency_list(string path);

#endif
