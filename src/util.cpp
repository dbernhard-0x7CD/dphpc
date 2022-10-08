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

        Edge e { u = stol(u_str), v = stol(v_str) };
        
        adj_list.push_back(e);
    }

    return adj_list;
}


