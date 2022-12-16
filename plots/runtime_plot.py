import os
import sys
import numpy as np

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from plotstyle import plotstyle
from plotloader import load_plot_data, arg_parse
from labellines import labelLines

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath
confidence_interval_flag = False

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_data(fullpath, include=include, exclude=exclude)
global_xaxis = set()
# del data["n"]

# apply similar styling across all plots
plotstyle()


# Draw plots
fig, ax = plt.subplots(figsize=(8.0, 8.0))
plt.xscale("log")
plt.yscale("log")

labels = list()
lines = list()
print("Including those functions: " + str(functions))
for func_name in functions:
    yaxis = data[func_name]
    xaxis = data[f"{func_name}_n"]
    global_xaxis = global_xaxis.union(xaxis)
    xlen = min(len(xaxis), len(yaxis))
    # print(func_name)
    # print(len(yaxis))
    if isinstance(data[func_name][0], list):
        q95 = lambda x: np.quantile(x, 0.95)
        q50 = lambda x: np.quantile(x, 0.5)
        q05 = lambda x: np.quantile(x, 0.05)
        y1 = list(map(q50, yaxis))
        y2 = list(map(q05, yaxis))
        y3 = list(map(q95, yaxis))
        c = ax.plot(xaxis, y1, label=func_name.replace("_"," "), marker=".")[0].get_color()
        # print(c)
        ax.fill_between(xaxis, y2, y3, alpha=0.2, zorder=1, color=c)
        confidence_interval_flag = True

    else:
        try:
            lines.append(ax.plot(xaxis, yaxis, label=func_name.replace("_"," "), marker="."))
            # plt.legend()
        except Exception as e:
            print (f"xaxis: {xaxis} and yaxis: {yaxis}")
            raise e

print("run e.g '$ python3 plots/runtime_plot.py -include add -exclude parallel' to show the runtime for add excluding parallel")

plt.xlabel("Input size [number of entries]")
plt.ylabel("Runtime [cycles]")

ax.set_xscale('log', base=2)
ax.set_yscale('log', base=2)

no_labels = len(data.keys())
xlabelpos = np.logspace(np.log2(sorted(global_xaxis)[-3]), np.log2(sorted(global_xaxis)[0]), no_labels, base=2)[1:-1]

# print(f"Max on x-axis: {max(global_xaxis)}")
labelLines(align=True, yoffsets=0.1, yoffset_logspace=True, xvals=xlabelpos)
# plt.legend(*zip(*labels), loc=2)

title = "Runtime Plot"

try:
    title  = include[0] + " " + title
except:
    pass

if confidence_interval_flag:
    title += ' (shaded area := 5% - 95% quantile area)'

plt.title(title)


if savepath:
    plt.savefig(os.path.join(os.getcwd(), savepath), pad_inches=0.1,  bbox_inches='tight', dpi=300)
else:
    plt.show()