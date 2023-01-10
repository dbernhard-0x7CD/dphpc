import os
import sys
from pprint import pprint

from plotloader import load_plot_dataframe, arg_parse

import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
from numpy import quantile

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_dataframe(fullpath, include=include, exclude=exclude)

def compute_mean(xs):
    aux = defaultdict(list)
    for x in xs:
        speedup = x % (10**5)
        n = (x-speedup) * (10**-5)
        aux[n].append(speedup)
        print(n, speedup)
    
    speedups = [quantile(y, 0.5) for y in aux.values()]

    return quantile(speedups, 0.5)

def compute_err(xs):
    aux = defaultdict(list)
    for x in xs:
        speedup = x % (10**5)
        n = (x-speedup) * (10**-5)
        aux[n].append(speedup)
        print(n, speedup)
    
    speedups = [(quantile(y, 0.05), quantile(y, 0.95)) for y in aux.values()]
    l1, l2 = zip(*speedups)
    return (quantile(l1, 0.5), quantile(l2, 0.5))

sns.set_style("dark")
ax = sns.barplot(data,
    x="category",
    y="speedup",
    hue="optimization",
    capsize=.1,
    estimator=compute_mean,
    errorbar=compute_err
)
ax.grid()

# plt.xticks(rotation = 45, ha='right')

if len(include) > 0:
    ax.set(title=include[0] + ' Speedup Plot')
else:
    ax.set(title='Speedup Plot')

plt.tight_layout()

if savepath:
    plt.savefig(os.path.join(os.getcwd(), savepath), pad_inches=0.1,  bbox_inches='tight', dpi=300)
else:
    plt.show()