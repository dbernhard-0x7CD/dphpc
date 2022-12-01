import argparse
import csv
import os
import sys
import json
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

# violin plots do not support out-of-the-box labels. this function fixes this
def violin_create_label(violin, label):
    color = violin["cmeans"].get_color().flatten()
    # color = violin["bodies"][3].get_facecolor().flatten()
    return (mpatches.Patch(color=color), label)

# Draw plots

fig, ax = plt.subplots(figsize=(6.4, 4.8))
plt.xscale("log")
plt.yscale("log")

labels = list()
lines = list()
for func_name in data.keys():
    yaxis = data[func_name]
    if isinstance(data[func_name][0], list):
        # v = ax.violinplot(
        #     yaxis, xaxis, 
        #     # ytest, xaxis, 
        #     widths=[x/4 for x in xaxis], 
        #     bw_method=0.5, points=15,
        #     showmeans=True, showmedians=True, showextrema=True
        # )
        # labels.append(violin_create_label(v, func_name))
        q95 = lambda x: np.quantile(x, 0.95)
        q50 = lambda x: np.quantile(x, 0.5)
        q05 = lambda x: np.quantile(x, 0.05)
        y1 = list(map(q50, yaxis))
        y2 = list(map(q05, yaxis))
        y3 = list(map(q95, yaxis))
        c = ax.plot(xaxis, y1, label=func_name, marker=".")[0].get_color()
        ax.fill_between(xaxis, y2, y3, alpha=0.2, zorder=1, color=c)
        confidence_interval_flag = True

    else:
        lines.append(ax.plot(xaxis, yaxis, label=func_name, marker="."))

plt.xlabel("Input size [number of entries]")
plt.ylabel("Runtime [cycles]")

ax.set_xscale('log', base=2)
ax.set_yscale('log', base=2)

no_labels = len(data.keys())
xlabelpos = np.logspace(np.log2(min(xaxis)), np.log2(max(xaxis)), no_labels+2, base=2)[1:-1]

# xlabelpos = [64*4**i for i in range(4)]
labelLines(align=True, yoffsets=0.1, yoffset_logspace=True, xvals=xlabelpos)
# plt.legend(*zip(*labels), loc=2)

try:
    plt.title(include[0] + " Runtime Plot")
except:
    plt.title("Runtime Plot")

if savepath:
    plt.savefig(fullpath + savepath, dpi=300)
else:
    plt.show()
