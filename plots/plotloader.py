import argparse
import os
import json
from itertools import compress

def load_plot_data(abspath, include=[], exclude=[]):
    files = list()
    data = dict()

    assert(os.path.isabs(abspath))
    # load all json files into list
    for filename in os.listdir(abspath):
        if filename.endswith(".json"):
            try:
                files = files + [json.load(open(abspath + filename, 'r'))]
            except:
                pass
    
    # merge all json dicts into one
    for json_file in files:
        for func_name in json_file.keys():
            data[func_name] = json_file[func_name]
    
    # filter keys according to inclue/exclude
    func_names = list(data.keys())
    func_names = arg_filter(func_names, include, exclude)
    tmp = {}
    tmp["n"] = data["n"]
    for fn in func_names:
        tmp[fn] = data[fn]
    data = tmp
    
    print("[    DATA LOADER]     loaded data for the plots {}".format(list(data.keys())))
    return data


def arg_parse():
    # add argparse to specify function names that should either be included or excluded
    parser = argparse.ArgumentParser()
    parser.add_argument("-include", type=str, nargs="*", dest="include",
                        help="Only function names containing a string from this list will be included, eg. sin")
    parser.add_argument("-exclude", type=str, nargs="*", dest="exclude",
                        help="Exclude all function names that contain a string from this list, eg. cosh")
    parser.add_argument("-save", type=str, nargs="?", dest="save", const="plot.png",
                        help="Save plot output instead of showing it, default filename is plot.png")
    args = parser.parse_args()
    return (args.include, args.exclude, args.save)

def arg_filter(x, include, exclude):
    x_filter = [True] * len(x)
    for i,k in enumerate(x):
        if k == "n":
            continue

        if include is not None and exclude is not None:
            if not all([inc in k for inc in include]) or any([exc in k for exc in exclude]):
                x_filter[i] = False
        elif include is not None:
            if not all([inc in k for inc in include]):
                x_filter[i] = False
        elif exclude is not None:
            if any([exc in k for exc in exclude]):
                x_filter[i] = False
    return list(compress(x, x_filter))
