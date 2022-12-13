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

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, save, builder, runner = arg_parse()
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
    print(f"Running benchmark \"{benchmark}\"")
    def create_shell():
        p = process(["/bin/bash"])  # env.sh relies on bash. sh is not sufficient

        p.sendline(b"pwd")          # print execution path
        print("pwd: ", p.recvline().decode())

        p.sendline(b"source ./scripts/env.sh")
        print("sourcing: ", p.recvline().decode())
 
        # This enables expansion of aliases (normally only in interactive shells)
        # p.sendline(b"shopt -s expand_aliases")
        return p
    
    p = create_shell()
    # start bash shell subprocess
    print("[SUBPROCESS]  starting bash shell")

    p.sendline(b"echo $PROOT")          # print project root
    print("proot: ", p.recvline().decode())

    # use shell to compile and run simulator
    print(f"[COMPILING] with builder: {builder}")
    
    p.sendline(bytes(f"{builder}; echo \"FINISHED COMPILING\""
, encoding="utf-8"))
    p.recvuntil(bytes("FINISHED COMPILING", encoding="utf-8"))

    print(f"[RUNNING]: {runner} (this takes a couple of minutes)")
    p.sendline(bytes(f"{runner} $PROOT/build/benchmark_{benchmark}; echo \"---SIMULATOR DONE---\"", encoding="utf-8"))

    result = p.recvuntil(b"---SIMULATOR DONE---").decode()

    # prints the console output of the benchmark. groups duplicate outputs
    unique_printer = defaultdict(int)
    for r in result.split("\n"):
        unique_printer[r] += 1
    for k, v in unique_printer.items():
        print("\t", v, "x", k)

    # parse result and values into dict
    sizes = set()
    data = dict()
    split_result = re.findall(r'\w+, \bsize: \b\d+: \b\d+\b cycles', result)
    tmp = defaultdict(lambda: defaultdict(list))
    for r in split_result:
        # parse a single line of the output and put it into tmp
        s = r.split(" ")
        cycles = int(s[-2])
        size = int(s[-3][:-1])
        name = s[0][:-1]

        sizes.add(size)
        # print("Adding size: " + str(size))
        tmp[name][size].append(cycles)
    
    # restructure tmp-dict into data-dict
    for k in tmp.keys():
        for l in tmp[k].keys():
            if all(x == tmp[k][l][0] for x in tmp[k][l]):
                tmp[k][l] = tmp[k][l][0]
    sizes = list(sizes)
    sizes.sort()
    # print(n)
    data["n"] = sizes

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

    p.sendline(bytes(f"exit 0", encoding="utf-8"))
