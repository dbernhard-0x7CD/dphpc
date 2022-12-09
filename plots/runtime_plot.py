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

include, exclude, savepath = arg_parse()
data = load_plot_data(fullpath, include=include, exclude=exclude)
xaxis = data["n"]
del data["n"]

# apply similar styling across all plots
plotstyle()


# Draw plots
fig, ax = plt.subplots(figsize=(6.4, 4.8))
plt.xscale("log")
plt.yscale("log")

labels = list()
lines = list()
for func_name in data.keys():
    yaxis = data[func_name]
    print(func_name)
    print(len(yaxis))
    if isinstance(data[func_name][0], list):
        q95 = lambda x: np.quantile(x, 0.95)
        q50 = lambda x: np.quantile(x, 0.5)
        q05 = lambda x: np.quantile(x, 0.05)
        y1 = list(map(q50, yaxis))
        y2 = list(map(q05, yaxis))
        y3 = list(map(q95, yaxis))
        c = ax.plot(xaxis, y1, label=func_name.replace("_"," "), marker=".")[0].get_color()
        print(c)
        ax.fill_between(xaxis, y2, y3, alpha=0.2, zorder=1, color=c)
        confidence_interval_flag = True

    else:
        lines.append(ax.plot(xaxis, yaxis, label=func_name.replace("_"," "), marker="."))

plt.xlabel("Input size [number of entries]")
plt.ylabel("Runtime [cycles]")

ax.set_xscale('log', base=2)
ax.set_yscale('log', base=2)

no_labels = len(data.keys())
xlabelpos = np.logspace(np.log2(min(xaxis)), np.log2(max(xaxis)), no_labels+2, base=2)[1:-1]

# xlabelpos = [64*4**i for i in range(4)]
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
    plt.savefig(fullpath + savepath, dpi=300)
else:
    plt.show()

print("run e.g '$ python3 plots/runtime_plot.py -include add -exclude parallel' to show the runtime for add excluding parallel")