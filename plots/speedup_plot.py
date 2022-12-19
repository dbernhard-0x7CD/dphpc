import os
import sys
import numpy as np
from Levenshtein import distance
from pprint import pprint
from statistics import median

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from plotstyle import plotstyle
from plotloader import load_plot_data, arg_parse
from collections import defaultdict

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath
confidence_interval_flag = False
FONTSIZE = 16

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_data(fullpath, include=include, exclude=exclude)

# aggregate nondeterministic values in data to their median
speedup_errs = {}
for k, v in data.items():
    speedup_errs[k] = list(map(lambda x: (np.quantile(x, 0.05), np.quantile(x, 0.95)) if isinstance(x, list) else (x,x), v))
    data[k] = list(map(lambda x: np.quantile(x, 0.5) if isinstance(x,list) else x, v))
    # print(data[k])

# finds all plot lines ending with "baseline"
baseline_names = [key for key in data.keys() if key.endswith("baseline")]
print(baseline_names)

# group data based on which baseline name matches theirs the closest 
grouping = defaultdict(list)
for implementation in data.keys():
    if implementation in baseline_names or implementation.endswith("_n"):
        continue
    else:
        baseline = min(baseline_names, key=lambda x:distance(x, implementation))
        grouping[baseline].append(implementation)

speedups = dict()

for baseline in grouping.keys():
    for implementation in grouping[baseline]:
        speedup = median([x[0] / x[1] for x in zip(data[baseline], data[implementation])])
        speedup_err = (
            median([x[0] / x[1][0] for x in zip(data[baseline], speedup_errs[implementation])]),
            median([x[0] / x[1][1] for x in zip(data[baseline], speedup_errs[implementation])])
        )
        speedup_errs[implementation] = speedup_err

        speedups[implementation] = speedup
        # print("{} {} {:.2f}".format(baseline, implementation, speedup))

# apply similar styling across all plots
plotstyle()

x_offsets = {}
counter = 0
for v in grouping.values():
    for x in v:
        x_offsets[x] = counter
        counter += 1
    counter += 1

plt_len = counter * 1.5
fig, ax = plt.subplots(figsize=(plt_len, 16.0))
# plt.xticks(rotation=90, fontsize=24)
plt.subplots_adjust(bottom=0.25)

width = 0.95

for i in range(max(map(len, grouping.values()))):
    bar_names = list(map(lambda x: x[i] if len(x) > i else False, grouping.values()))
    
    y_axis = [speedups[x] for x in bar_names if x]
    x_axis = [x_offsets[x] for x in bar_names if x]

    ax.bar(x_axis, y_axis, width=width)

ax.plot([-width/2, counter-2+(width/2)], [1,1], '--', color='gray')

# labels = [y for x in grouping.values() for y in x + [""]]
# labels = labels[:-1]
# print(labels)
pprint(x_offsets)
labels = [""] * (max(x_offsets.values()) + 1)
for k,v in x_offsets.items():
    labels[v] = k
    # print()

for label in labels:
    try:
        xpos = x_offsets[label]
        ax.text(
            xpos, 
            2**(-2.6), 
            "  {} ({:.2f}x)".format(label, speedups[label]), 
            ha="center", va="top", fontsize=FONTSIZE, rotation=90)
        ax.plot([xpos, xpos], speedup_errs[label], color='red')
    except: pass

ax.set_xticklabels([])
ax.set_yscale('log', base=2)
plt.ylabel("Speedup factor (Baseline = 1)", fontsize=FONTSIZE)

plt.title("Speedup Plot (Red line = 5% - 95% quantile)", fontsize=FONTSIZE)

plt.show()
