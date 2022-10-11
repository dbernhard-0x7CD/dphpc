#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/rmat_graph_generator.hpp>
#include <boost/random/linear_congruential.hpp>

#include "main.hpp"

typedef boost::rmat_iterator<boost::minstd_rand, uGraph> RMATGen;

uGraph generate_rmat(const size_t n, const size_t m)
{
    boost::minstd_rand gen;
    gen.seed(421);

    // Create graph with 100 nodes and 400 edges
    uGraph g(RMATGen(gen, n, m, 0.07, 0.19, 0.19, 0.05), RMATGen(), 100);

    // graph g probably ocntains parallel edges.
    uGraph gret(num_vertices(g));

    graph_traits< uGraph >::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei)
    {
        graph_traits< uGraph >::edge_descriptor e = *ei;
        graph_traits< uGraph >::vertex_descriptor u = source(e, g),
                                                   v = target(e, g);
        // Uncomment for debugging purposes:
        // cout << "Edge: " << u << " -- " << v << endl;

        bool exists = edge(u, v, gret).second;
        if (!exists) {
            add_edge(u, v, gret);
        }
    }
    return gret;
}