#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>
#include <boost/graph/undirected_graph.hpp>
#include <set>
#include <string>
#include <fstream>
#include <iostream>
#include <utility>

#include "main.hpp"
#include "test.hpp"
#include "util.hpp"

using namespace boost;
using namespace std;

/*
 * Loads vertices into vector from adjacency list. 
 * And also stores them as dot file at './out.dot' for
 * the visualization of the graph.
 */
void load_and_store() {
    // load adjacency list from file into a vector
    std::string filename = "../data/adj_list_small_graph.txt";

    // test_graph_read_write(filename);
    vector<Edge> adj = load_from_adjacency_list(filename);

    uGraph g = adjacency_list_to_ugraph(adj);

    store_ugraph_as_dot("./out.dot", g);
}

/*
 * Creates some graph and stores it as dot file at 'output_file'
 */
void build_graph_and_store(string output_file) {
    uGraph g;

    ColorProperty red;
    red.color = "red";

    add_edge(4, 5, red, g);
    add_edge(4, 3, red, g);
    add_edge(3, 2, red, g);
    add_edge(2, 1, red, g);
    add_edge(4, 6, red, g);
    add_edge(4, 0, red, g);
    add_edge(0, 8, red, g);
    add_edge(8, 7, red, g);
    add_edge(0, 9, red, g);
    add_edge(0, 10, red, g);

    store_ugraph_as_dot(output_file, g);
}

/*
 * Stores the graph at filename (should end with ".dot")
 * You can render it with dot using: `dot -Tpng filename -o outfile.png`
 */
void store_ugraph_as_dot(string filename, uGraph g) {
    ofstream fs(filename);

    boost::dynamic_properties dp;

    dp.property("color", get(&ColorProperty::color, g));
    dp.property("node_id", get(boost::vertex_index, g));

    write_graphviz_dp(fs, g, dp);
    fs.close();
}
