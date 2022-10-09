
#ifndef TEST_H
#define TEST_H

#include <boost/config/detail/suffix.hpp>
#include <iostream>
#include <string>

#include "main.hpp"

using namespace boost;
using namespace std;

void test_graph_read_write(const string& filename);

void load_and_store();

void store_ugraph_as_dot(string filename, uGraph &g);

void build_graph_and_store(string output_file);

void test_combine();

#endif
