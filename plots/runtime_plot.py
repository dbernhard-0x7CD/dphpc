import os
import sys
import numpy as np

import matplotlib.pyplot as plt
plt.style.use('seaborn-darkgrid')

import seaborn as sns
# sns.set(rc = {'figure.figsize':(16,12)})

from plotloader import load_plot_dataframe, arg_parse
from collections import defaultdict

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_dataframe(fullpath, include=include, exclude=exclude)

plt.xscale('log', base=2)
plt.yscale('log', base=2)

sns.set_style("dark")
ax = sns.lineplot(data, x='n', y='cycles', 
    hue="optimization", 
    style="parallelism",
    markers=True, 
    estimator=np.median, 
    errorbar=lambda x:(np.quantile(x, 0.10), np.quantile(x, 0.90)))

ax.set(xlabel='input size', ylabel='runtime [cycles]')

if len(include) > 0:
    ax.set(title=include[0] + ' Runtime Plot')
else:
    ax.set(title='Runtime Plot')

if savepath:
    plt.savefig(os.path.join(os.getcwd(), savepath), pad_inches=0.1,  bbox_inches='tight', dpi=300)
else:
    plt.show()
