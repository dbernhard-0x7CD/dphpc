
#ifndef MAIN_H
#define MAIN_H

#include <boost/graph/adjacency_list.hpp>
#include <boost/config/detail/suffix.hpp>  // for boost
#include <boost/graph/properties.hpp>      // for vertex_name_t
#include <boost/pending/property.hpp>      // for property
#include <iosfwd>                          // for std
#include <string>                          // for string
namespace boost { struct undirectedS; }

using namespace boost;
using namespace std;

/* Only tests for the functionality of MPI and OMP. */
void mpi_reduction();
void omp_reduction();

/*
 * May be used to add color in dot files (they can be visualized using xdot)
 * Used for edges inside a graph
 */
struct ColorProperty {
    string color;
};

struct Node
{
    unsigned long id;
};

// Necessary for struct Node
bool operator <(const Node& x, const Node& y);

/*
 * Graph representation for storing an undirected graph. Uses an adjacency list
 * for internal storage.
 */
typedef adjacency_list<vecS, vecS, undirectedS, property<vertex_name_t, string>, ColorProperty> uGraph;

/*
 * Weighted undirected graph. Used for calculating the MST.
 */
typedef adjacency_list<vecS, vecS, undirectedS, property<vertex_name_t, string>, property<edge_weight_t, int>> wuGraph;

typedef graph_traits< uGraph >::vertex_descriptor Vertex;

/* An undirected edge between u and v. */
struct Edge {
    unsigned long u;
    unsigned long v;
};

#endif
