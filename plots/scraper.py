from pwn import *
from collections import defaultdict
import re
import csv
import os
import sys
import argparse
import json
from itertools import compress
from plotloader import arg_parse, arg_filter

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
benchmarks = arg_filter(benchmarks, include, exclude)

# start simulator for each of the names in benchmarks
print("[INFO]   simulating the operators: ", benchmarks)
for i, benchmark in enumerate(benchmarks):
    # start bash shell subprocess
    print("[SUBPROCESS  ] starting bash shell")
    p = process(["/bin/bash"])  # env.sh relies on bash. sh is not sufficient
    p.sendline(b"pwd")          # print execution path
    print("pwd: ", p.recvline().decode())
    data = dict()
    # data["n"] = [2**i for i in range(5, input_size+1)]
    n = set()

    # use shell to compile and run simulator
    print("[COMPILING]  with input size up to " + str(2**input_size))
    p.sendline(bytes("./scripts/bench.sh " + str(2**input_size) + " build/benchmark_" + benchmark, encoding="utf-8"))
    p.recvuntil(b"---RUNNING SIMULATOR---") # voids output of compiler
    print("[RUNNING]    " + benchmark + " (this takes a couple of minutes)")
    # result = ""
    # line = ""
    # while "---SIMULATOR DONE---" not in line:
    #     line = p.recvline().decode()
    #     print("\t",line.replace("\n", ""))
    #     result += line
    result = p.recvuntil(b"---SIMULATOR DONE---").decode()

    # prints the console output of the benchmark. groups duplicate outputs
    unique_printer = defaultdict(int)
    for r in result.split("\n"):
        unique_printer[r] += 1
    for k, v in unique_printer.items():
        print("\t", v, "x", k)

    # parse result and values into dict
    split_result = re.findall(r'\w+, \bsize: \b\d+: \b\d+\b cycles', result)
    tmp = defaultdict(lambda: defaultdict(list))
    for r in split_result:
        # parse a single line of the output and put it into tmp
        s = r.split(" ")
        cycles = int(s[-2])
        size = int(s[-3][:-1])
        name = s[0][:-1]

        n.add(size)
        tmp[name][size].append(cycles)
    
    # restructure tmp-dict into data-dict
    for k in tmp.keys():
        for l in tmp[k].keys():
            if all(x == tmp[k][l][0] for x in tmp[k][l]):
                tmp[k][l] = tmp[k][l][0]

    n = list(n)
    n.sort()
    # print(n)
    data["n"] = n

    for k in tmp.keys():
        # data[k].append(tmp[k])
        data[k] = [tmp[k][l] for l in sorted(tmp[k].keys())] # would technically work without sorting, but I dont like relying on the implementation detail that dict-keys are sorted by insertion order in python
    
    # print progress
    full = len(benchmarks)
    print("[PROGRESS]   {:3.2%} Done ({}/{})".format((i+1) / full ,i+1 ,full))
    
    # save data as json file
    filename = "plots/data/" + benchmark + "_runtime.json"
    with open(filename, "w") as jsonfile:
        jsonfile.write(json.dumps(data, indent=4))