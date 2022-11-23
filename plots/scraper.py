from pwn import *
from collections import defaultdict
import re
import csv
import os

input_sizes = [32, 48, 64, 96, 128, 192, 256, 384, 512]

# finds all relevant benchmark names
benchmarks = []
fullpath = os.path.dirname(__file__) + "/../build"
for filename in os.listdir(fullpath):
    if "benchmark" in filename and not (filename.endswith(".a") or filename.endswith(".s")):
        benchmarks.append(filename.replace("benchmark_", ""))

# TODO: speed up implementation by spawning processes in parallel instead of sequentially
print("[INFO]   simulating the operators: "+ benchmarks)
for i, benchmark in enumerate(benchmarks):
    filename = "plots/data/" + benchmark + "_runtime.csv"

    # start bash shell subprocess
    print("[SUBPROCESS  ] starting bash shell")
    p = process(["/bin/bash"])  # env.sh relies on bash. sh is not sufficient
    p.sendline(b"pwd")          # print execution path
    print("pwd: ", p.recvline().decode())

    data = defaultdict(list)

    for j, n in enumerate(input_sizes):

        # use shell to compile and run simulator
        print("[COMPILING]  " + benchmark + " with input size = " + str(n))
        p.sendline(bytes("./scripts/bench.sh " + str(n) + " build/benchmark_" + benchmark, encoding="utf-8"))
        p.recvuntil(b"---RUNNING SIMULATOR---") # voids output of compiler
        print("[RUNNING]    " + benchmark)
        result = p.recvuntil(b"---SIMULATOR DONE---").decode()
        print(result.replace("\n", "\n\t"))

        # parse result and values into dict
        data["n"].append(n)
        split_result = re.findall(r'\w+, \bsize: \b\d+: \b\d+\b cycles', result)
        for r in split_result:
            s = r.split(" ")
            cycles = int(s[-2])
            name = s[0][:-1].replace("_", " ")
            data[name].append(cycles)

        # print progress of the simulator
        full = len(benchmarks) * len(input_sizes)
        print("[PROGRESS]   {:3.2%} Done ({}/{})".format((i*len(input_sizes)+j+1) / full ,(i*len(benchmarks)+j+1),full))
    
    # store dict as csv
    print("[WRITING CSV] ", filename)
    with open(filename, "w") as csvfile:
        writer = csv.writer(csvfile, delimiter=",")
        writer.writerow(data.keys())
        for i, n in enumerate(data["n"]):
            r = []
            for k in data.keys():
                r.append(data[k][i])
            writer.writerow(r)