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
        Edge e { .u = u, .v = v };
        
        adj_list.push_back(e);
    }

    return adj_list;
}

void store_adjacency_list(string path, vector<Edge> adj_list) {
    ofstream os(path);

    for (Edge e : adj_list) {
        os << e.u.id << " " << e.v.id << ::endl;
    }
    os.close();
}

uGraph adjacency_list_to_ugraph(vector<Edge> adj_list) {
    size_t max = 0;
    for (auto const& e : adj_list) {
        if (e.u.id > max) {
            max = e.u.id;
        }
        if (e.v.id > max) {
            max = e.v.id;
        }
    }
    // as 0 is also a vertex
    max++;

    cout << "Creating graph with " << max << " vertices" << std::endl;
    set<Node> nodes;
    
    // Actually not needed to have an accurate size when initializing
    uGraph g(max);

    for (auto const& e : adj_list) {
        if (nodes.find(e.u) == nodes.end()) {
            nodes.insert(e.u);
        }
        if (nodes.find(e.v) == nodes.end()) {
            nodes.insert(e.v);
        }
        
        // cout << "Edge " << e.u << " --- " << e.v << std::endl;
    }
    cout << "Amount of edges: " << adj_list.size() << std::endl;
    cout << "Amount of nodes: " << nodes.size() << std::endl;
    
    for (auto const& e : adj_list) {
        add_edge(e.u.id, e.v.id, g);
    }

    return g;
}