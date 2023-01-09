import os
import sys
from pprint import pprint

from plotloader import load_plot_dataframe, arg_parse

import matplotlib.pyplot as plt
import seaborn as sns

relpath = "data/"
fullpath = os.path.dirname(__file__) + "/" + relpath

if ".git" not in os.listdir(os.getcwd()):
    print("please run this script from the project root")
    sys.exit()

include, exclude, savepath, _, _ = arg_parse()
functions, data = load_plot_dataframe(fullpath, include=include, exclude=exclude)

sns.set_style("dark")
ax = sns.barplot(data,
    x="category",
    y="speedup",
    hue="optimization",
    capsize=.1
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