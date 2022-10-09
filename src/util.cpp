#include <boost/graph/graphviz.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/undirected_graph.hpp>

#include "main.hpp"
#include "util.hpp"

vector<Edge> load_from_adjacency_list(string path) {
    vector<Edge> adj_list(100);
    adj_list.resize(0);

    ifstream is(path);
    string line;
    string u_str, v_str;

    int char_len = 0;
    int offset_v = 0;
    long u, v;
    while(getline(is, line))
    {
        char_len = 0;

        char* head = (char *) line.c_str();

        while (*head >= '0' && *head <= '9') {
            head++;
            char_len++;
        }
        // head points now to the first non decimal character
        string u_str = line.substr(0, char_len);

        while (!(*head >= '0' && *head <= '9')) {
            head++;
            char_len++;
        }
        offset_v = char_len;
        char_len = 1;

        while (*head >= '0' && *head <= '9') {
            head++;
            char_len++;
        }

        string v_str = line.substr(offset_v, char_len);

        Node u = { .id = stoul(u_str) };
        Node v = { .id = stoul(v_str) };
        Edge e { .u = u.id, .v = v.id };
        
        adj_list.push_back(e);
    }

    return adj_list;
}

void store_adjacency_list(string path, const vector<Edge> &adj_list) {
    ofstream os(path);

    for (Edge e : adj_list) {
        os << e.u << " " << e.v << ::endl;
    }
    os.close();
}

uGraph adjacency_list_to_ugraph(const vector<Edge> &adj_list) {
    size_t max = 0;
    for (auto const& e : adj_list) {
        if (e.u > max) {
            max = e.u;
        }
        if (e.v > max) {
            max = e.v;
        }
    }
    // as 0 is also a vertex
    max++;

    cout << "Creating graph with " << max << " vertices" << std::endl;
    set<Node> nodes;
    
    // Actually not needed to have an accurate size when initializing
    uGraph g(max);

    for (auto const& e : adj_list) {
        Node node_u { .id = e.u };
        Node node_v { .id = e.v };

        if (nodes.find(node_u) == nodes.end()) {
            nodes.insert(node_u);
        }
        if (nodes.find(node_v) == nodes.end()) {
            nodes.insert(node_v);
        }
        
        // cout << "Edge " << e.u << " --- " << e.v << std::endl;
    }
    cout << "Amount of edges: " << adj_list.size() << std::endl;
    cout << "Amount of nodes: " << nodes.size() << std::endl;
    
    for (auto const& e : adj_list) {
        add_edge(e.u, e.v, g);
    }

    return g;
}
