#ifndef LMQ_UTILS_H
#define LMQ_UTILS_H


#include <iostream>
#include <string.h>
#include <vector>

#include "main.hpp"

using namespace std;

/*
 * Loads a file with edges in the form "X Y" per line into a vector of Edges.
 * X,Y must fit into an unsigned long. And there may be multiple spaces between X and Y.
 * 
 * Returns: vector of edges
 * WHY: To load edges from a library which generates graphs.
 * NOTE: This may not be fully optimized
 */
vector<Edge> load_from_adjacency_list(string path);

/*
 * Stores the adjacency list in the file defined by `path`.
 * Each edge will be on a line in the form "X Y"
 * 
 * WHY: To store edges in a file. (pendand to load_from_adjacency_list)
*/
void store_adjacency_list(string path, vector<Edge> &adj_list);

/*
 * Converts the adjacency list into an uGraph.
 */
uGraph adjacency_list_to_ugraph(vector<Edge> &adj_list);

#endif
