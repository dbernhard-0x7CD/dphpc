import os
import sys
from pprint import pprint

from plotloader import load_plot_dataframe, arg_parse

import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
from numpy import quantile as npquantile

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _, _ = arg_parse()
functions, data = load_plot_dataframe(fullpath, include=include, exclude=exclude)

data = data[data.apply(lambda x: "baseline" not in x["implementation name"], axis=1)]
# computes a weighted quantile
def wquantile(values, weights, p):
    x = sum(weights) * p
    i = 0
    while x > 0:
        x -= weights[i]
        i += 1
    i -= 1
    return values[i]

def compute_mean(xs):
    if len(xs) == 0:
        return 0

    aux = defaultdict(list)
    for x in xs:
        speedup = x % (10**5)
        n = (x-speedup) * (10**-5)
        aux[n].append(speedup)
    
    speedups = [npquantile(y, 0.5) for y in aux.values()]

    return wquantile(speedups, list(aux.keys()), 0.5)

def compute_err(xs):
    if len(xs) == 0:
        return (0,0)

    aux = defaultdict(list)
    for x in xs:
        speedup = x % (10**5)
        n = (x-speedup) * (10**-5)
        aux[n].append(speedup)
    
    speedups = [(npquantile(y, 0.05), npquantile(y, 0.95)) for y in aux.values()]
    l1, l2 = zip(*speedups)
    return (wquantile(l1, list(aux.keys()), 0.5), wquantile(l2, list(aux.keys()), 0.5))

sns.set_style("dark")
fig_len = len(data["implementation name"].unique()) / 2
fig, ax = plt.subplots(figsize=(fig_len, 6))

# print(data)
sns.barplot(data,
    ax=ax,
    x="category",
    y="speedup",
    hue="optimization",
    hue_order=["none", "ssr", "ssr+frep"],
    capsize=.1,
    estimator=compute_mean,
    errorbar=compute_err
)
ax.grid()

for x in ax._children:
    print(x)
    print(x.__dict__) 

plt.xticks(rotation = 45, ha='right', fontsize=11)

if include is not None and len(include) > 0:
    ax.set(title=include[0] + ' Speedup Plot')
else:
    ax.set(title='Speedup Plot')

ax.set(xlabel='operator', ylabel='median speedup')

plt.tight_layout()

if savepath:
    plt.savefig(os.path.join(os.getcwd(), savepath), pad_inches=0.1,  bbox_inches='tight', dpi=300)
else:
    plt.show()
