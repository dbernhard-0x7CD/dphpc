import argparse
import csv
import os

import matplotlib.pyplot as plt

from plotstyle import plotstyle
from labellines import labelLines

csv_files = list()
func_names = list()
xaxis = list()
yaxes = list()

relpath = "data/"

# add argparse to specify function names that should either be included or excluded
parser = argparse.ArgumentParser()
parser.add_argument("-include", type=str, nargs="*", dest="include",
                    help="Only function names containing a string from this list will be included, eg. F_simd")
parser.add_argument("-exclude", type=str, nargs="*", dest="exclude",
                    help="Exclude all function names that contain a string from this list, eg. block or 50%%")
parser.add_argument("-save", type=str, nargs="?", dest="save", const="plot.png",
                    help="Save plot output instead of showing it, default filename is plot.png")
args = parser.parse_args()

print("[ INFO   ]use $ python runtime_plot.py -h   for help")

# open csv readers for all csv files in the directory
for filename in os.listdir(os.getcwd() + "/" + relpath):
    if filename.endswith(".csv"):
        try:
            csv_files = csv_files + [csv.reader(open(relpath + filename), delimiter=",")]
        except:
            pass

# read data from all csv files and dump into arrays
func_names = []
for csv_file in csv_files:
    header = next(csv_file)
    csv_func_names = header[1::]
    csv_yaxes = []
    print("[    AVAILABLE PLOTS     ]", csv_func_names)

    for _ in range(len(csv_func_names)):
        csv_yaxes.append(list())

    for line in csv_file:
        if(len(line) == 0):
            continue # skip empty lines
        xaxis.append(int(line[0]))
        for i, x in enumerate(line[1::]):
            csv_yaxes[i].append(int(x))
    
    func_names = func_names + csv_func_names
    yaxes = yaxes + csv_yaxes

xaxis = xaxis[:len(yaxes[0])]

# quick'n'dirty way to check if list of strings matches a function name
# eg. "E_block10 (25%)" matches ["block", "25%"]
def is_substring_in_list(input_string, input_list):
    for list_item in input_list:
        if input_string.find(list_item) != -1:
            return True
    return False

# Filter list of function names by a whitelist and a blacklist
# This allows to specify certain graph sizes or function types,
# eg. to only compare edge_it and forward_it for graphs with 25% connectivity, set arguments -include 25% -exclude FH_
indices = list(range(len(func_names)))
if args.include:
    indices = [i for i in indices if is_substring_in_list(func_names[i], args.include)]
if args.exclude:
    indices = [i for i in indices if not is_substring_in_list(func_names[i], args.exclude)]
func_names = [func_names[i] for i in indices]
yaxes = [yaxes[i] for i in indices]

n_functions = len(func_names)

# compute avg speedups compared to first yaxis
for li in range(n_functions):
    speedup_arr = []
    label = func_names[li]
    for i in range(len(yaxes[0])):
        speedup_arr.append(yaxes[0][i] / yaxes[li][i])
    print("[    SPEEDUP     ]", label, "speedup vs.", func_names[0], ":", sum(speedup_arr) / len(speedup_arr))



# apply similar styling across all plots
plotstyle()

# Draw plots
fig, ax = plt.subplots(figsize=(6.4, 4.8))

for i in range(n_functions):
    ax.plot(xaxis, yaxes[i], label=func_names[i], marker=".")

plt.xlabel("Input size [number of entries]")
plt.ylabel("Runtime [cycles]")

ax.set_xscale('log', base=2)
ax.set_yscale('log', base=2)

labelLines(align=True, yoffsets=130)

try:
    plt.title(args.include[0] + " Runtime Plot (1 CPU)")
except:
    plt.title("Runtime Plot (1 CPU)")


if args.save:
    plt.savefig(relpath + args.save, dpi=300)
else:
    plt.show()
