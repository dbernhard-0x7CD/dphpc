#include <boost/graph/graphviz.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/undirected_graph.hpp>
#include <iostream>

#include "main.hpp"
#include "util.hpp"

vector<Edge> load_from_adjacency_list(string path) {
    vector<Edge> adj_list(100);
    adj_list.resize(0);

    ifstream is(path);
    string line;
    string u_str, v_str;

    if (!is.good()) {
        char err[64];
        snprintf(err, 64, "File %s does not exist!", path.c_str()); 
        throw runtime_error(err);
    }

    int char_len = 0;
    int offset_v = 0;
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

    for (auto const &e : adj_list) {
        os << e.u << " " << e.v << ::endl;
    }
    os.close();
}

uGraph adjacency_list_to_ugraph(const vector<Edge> &adj_list) {
    // Find out what is the maximum node referenced
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
        if (e.u == e.v) continue;
        bool exists = edge(e.u, e.v, g).second;
        if (!exists) {
            add_edge(e.u, e.v, g);
            // cout << "Adding edge " << e.u << " --- " << e.v << endl;
        }
    }

    return g;
}

wuGraph adjacency_list_to_wugraph(const vector<Edge> &adj_list) {
    // Find out what is the maximum node referenced
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
    wuGraph g(max);
    
    for (auto const& e : adj_list) {
        if (e.u == e.v) continue;
        bool exists = edge(e.u, e.v, g).second;
        if (!exists) {
            // cout << "Adding edge " << e.u << " --- " << e.v << endl;
            add_edge(e.u, e.v, 1, g);
        }
    }

    return g;
}
