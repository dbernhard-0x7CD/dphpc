from pwn import *
from collections import defaultdict
import re
import csv
import os
import sys
import argparse
import json

# input_sizes = [32, 64, 128, 256, 512]
input_sizes = [2**i for i in range(5, 13)]
no_runs = 25

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

# add argparse to specify function names that should either be included or excluded
parser = argparse.ArgumentParser()
parser.add_argument("-include", type=str, nargs="*", dest="include",
                    help="Only operators names containing a string from this list will be sun, eg. sin")
args = parser.parse_args()

def is_substring_in_list(input_string, input_list):
    for list_item in input_list:
        if input_string.find(list_item) != -1:
            return True
    return False

# finds all relevant benchmark names
benchmarks = []
fullpath = os.path.dirname(__file__) + "/../build"
for filename in os.listdir(fullpath):
    if "benchmark" in filename and not (filename.endswith(".a") or filename.endswith(".s")):
        benchmarks.append(filename.replace("benchmark_", ""))

indices = list(range(len(benchmarks)))
if args.include:
    indices = [i for i in indices if is_substring_in_list(benchmarks[i], args.include)]
    benchmarks = [benchmarks[i] for i in indices]

print("[INFO]   simulating the operators: ", benchmarks)
for i, benchmark in enumerate(benchmarks):
    # start bash shell subprocess
    print("[SUBPROCESS  ] starting bash shell")
    p = process(["/bin/bash"])  # env.sh relies on bash. sh is not sufficient
    p.sendline(b"pwd")          # print execution path
    print("pwd: ", p.recvline().decode())

    data = defaultdict(list)
    data["n"] = input_sizes

    for j, n in enumerate(input_sizes):

        # use shell to compile and run simulator
        print("[COMPILING]  " + benchmark + " with input size = " + str(n))
        p.sendline(bytes("./scripts/bench.sh " + str(n) + " build/benchmark_" + benchmark + " " + str(no_runs), encoding="utf-8"))
        p.recvuntil(b"---RUNNING SIMULATOR---") # voids output of compiler
        print("[RUNNING]    " + benchmark)
        result = p.recvuntil(b"---SIMULATOR DONE---").decode()
        print(result.replace("\n", "\n\t"))

        # parse result and values into dict
        split_result = re.findall(r'\w+, \bsize: \b\d+: \b\d+\b cycles', result)
        tmp = defaultdict(list)
        for r in split_result:
            s = r.split(" ")
            cycles = int(s[-2])
            name = s[0][:-1].replace("_", " ")
            tmp[name].append(cycles)
        for k in tmp.keys():
            if all(x == tmp[k][0] for x in tmp[k]):
                tmp[k] = tmp[k][0]

        for k in tmp.keys():
            data[k].append(tmp[k])

        # print progress of the simulator
        full = len(benchmarks) * len(input_sizes)
        print("[PROGRESS]   {:3.2%} Done ({}/{})".format((i*len(input_sizes)+j+1) / full ,(i*len(benchmarks)+j+1),full))
    
    filename = "plots/data/" + benchmark + "_runtime.json"
    with open(filename, "w") as jsonfile:
        jsonfile.write(json.dumps(data, indent=4))