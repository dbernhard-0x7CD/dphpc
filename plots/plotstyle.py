import matplotlib.pyplot as plt
from cycler import cycler

def plotstyle():
    # plt.style.use("seaborn-darkgrid")
    colors = cycler('color',
                    ['#2E604A', '#27223C', '#A35E60',
                    '#D1362F', '#541F12', '#957A6D'])
    plt.rc('axes', facecolor='#E6E6E6', edgecolor='none',
        axisbelow=True, grid=True, prop_cycle=colors)
    # plt.rc('axes', facecolor='#E6E6E6', edgecolor='none',
        #    axisbelow=True, grid=True)
    plt.rc('grid', color='w', linestyle='solid')
    plt.rc('xtick', direction='out', color='gray')
    plt.rc('ytick', direction='out', color='gray')
    plt.rc('patch', edgecolor='#E6E6E6')
    plt.rc('lines', linewidth=2)