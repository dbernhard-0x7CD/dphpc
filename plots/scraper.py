from pwn import *
from collections import defaultdict
import re
import csv
import os
import sys
import argparse
import json
from itertools import compress
from plotloader import arg_parse

# input_sizes = [32, 64, 128, 256, 512]
# input_sizes = [2**i for i in range(5, 13)]
input_size = 12

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, save = arg_parse()
# add argparse to specify function names that should either be included or excluded

# finds all relevant benchmark names
benchmarks = []
fullpath = os.path.dirname(__file__) + "/../build"
for filename in os.listdir(fullpath):
    if "benchmark" in filename and not (filename.endswith(".a") or filename.endswith(".s")):
        benchmarks.append(filename.replace("benchmark_", ""))

# filter benchmark names based on include, exclude
benchmarks_filter = [True] * len(benchmarks)
for i,k in enumerate(benchmarks):
    if k == "n":
        continue

    if include is not None and exclude is not None:
        if not all([inc in k for inc in include]) or any([exc in k for exc in exclude]):
            benchmarks_filter[i] = False
    elif include is not None:
        if not all([inc in k for inc in include]):
            benchmarks_filter[i] = False
    elif exclude is not None:
        if any([exc in k for exc in exclude]):
            benchmarks_filter[i] = False

benchmarks = list(compress(benchmarks, benchmarks_filter))

# start simulator for each of the names in benchmarks
print("[INFO]   simulating the operators: ", benchmarks)
for i, benchmark in enumerate(benchmarks):
    # start bash shell subprocess
    print("[SUBPROCESS  ] starting bash shell")
    p = process(["/bin/bash"])  # env.sh relies on bash. sh is not sufficient
    p.sendline(b"pwd")          # print execution path
    print("pwd: ", p.recvline().decode())
    data = dict()
    data["n"] = [2**i for i in range(5, input_size+1)]


    # use shell to compile and run simulator
    print("[COMPILING]  everything with input size up to " + str(2**input_size))
    p.sendline(bytes("./scripts/bench.sh " + str(2**input_size) + " build/benchmark_" + benchmark, encoding="utf-8"))
    p.recvuntil(b"---RUNNING SIMULATOR---") # voids output of compiler
    print("[RUNNING]    " + benchmark)
    result = p.recvuntil(b"---SIMULATOR DONE---").decode()
    unique_printer = defaultdict(int)
    for r in result.split("\n"):
        unique_printer[r] += 1
    for k, v in unique_printer.items():
        print("\t", v, "x", k)
    # print(result.replace("\n", "\n\t"))

    # parse result and values into dict
    split_result = re.findall(r'\w+, \bsize: \b\d+: \b\d+\b cycles', result)
    tmp = defaultdict(lambda: defaultdict(list))
    for r in split_result:
        s = r.split(" ")
        cycles = int(s[-2])
        size = int(s[-3][:-1])
        name = s[0][:-1].replace("_", " ")
        tmp[name][size].append(cycles)
    for k in tmp.keys():
        for l in tmp[k].keys():
            if all(x == tmp[k][l][0] for x in tmp[k][l]):
                tmp[k][l] = tmp[k][l][0]
    
    for k in tmp.keys():
        # data[k].append(tmp[k])
        data[k] = [tmp[k][l] for l in sorted(tmp[k].keys())]
    
    full = len(benchmarks)
    print("[PROGRESS]   {:3.2%} Done ({}/{})".format((i+1) / full ,i+1 ,full))
    
    filename = "plots/data/" + benchmark + "_runtime.json"
    with open(filename, "w") as jsonfile:
        jsonfile.write(json.dumps(data, indent=4))