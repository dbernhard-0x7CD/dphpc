import os
import sys
import numpy as np

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from plotstyle import plotstyle
from plotloader import load_plot_data, arg_parse
from collections import defaultdict
from difflib import get_close_matches

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath
confidence_interval_flag = False

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath = arg_parse()
functions, data = load_plot_data(fullpath, include=include, exclude=exclude)
del data["n"]

# finds all plot lines with "baseline" in their name
baseline_names = [key for key in data.keys()if "baseline" in key]
for b in baseline_names:
    print(b)
labels = defaultdict(list)
for k in data.keys():
    if k in baseline_names:
        continue
    print(k, (k, [b.replace("baseline", "") for b in baseline_names]))


# apply similar styling across all plots
plotstyle()
