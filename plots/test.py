import os
import sys
import numpy as np
from Levenshtein import distance
from pprint import pprint
from statistics import median

import matplotlib.pyplot as plt
plt.style.use('seaborn-darkgrid')

import seaborn as sns
import pandas as pd

from plotstyle import plotstyle
from plotloader import load_plot_dataframe, arg_parse
from collections import defaultdict

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_dataframe(fullpath, include=include, exclude=exclude)
# pprint(data)


plt.xscale('log', base=2)
plt.yscale('log', base=2)

sns.set()
sns.set_style("dark")
sns.lineplot(data, x='n', y='cycles', hue="implementation name", markers=True, estimator=np.median, errorbar=lambda x:(np.quantile(x, 0.10), np.quantile(x, 0.90)))

plt.show()

