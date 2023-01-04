import argparse
import os
import json
from itertools import compress
import pandas as pd

'''
Loads all *.json files in abspath and returns a list of functions and a dictionary with all runtime-cycles.
'''
def load_plot_data(abspath, include=[], exclude=[]):
    files = list()
    data = dict()
    functions = list()

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
            if func_name == "n": continue
            functions.append(func_name)
            data[func_name] = json_file[func_name]
            data[f"{func_name}_n"] = json_file["n"]
    
    # filter keys according to inclue/exclude
    func_names = list(data.keys())
    func_names = arg_filter(func_names, include, exclude)
    tmp = {}
    # tmp["n"] = data["n"]
    for fn in func_names:
        if fn == "n": continue
        tmp[fn] = data[fn] 
    data = tmp
    
    functions = arg_filter(functions, include, exclude)
    print("[    DATA LOADER]     loaded data for the plots {}".format(list(data.keys())))
    return functions, data

def load_plot_dataframe(abspath, include=[], exclude=[]):
    files = list()
    data = dict()
    functions = list()

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
            if func_name == "n": continue
            functions.append(func_name)
            if isinstance(json_file[func_name][0], list):
                x = [{"n": int(ni), "cycles": int(ci)} for (ni, cii) in zip(json_file["n"], json_file[func_name]) for ci in cii]
                data[func_name] = x
            else:
                x = [{"n": int(ni), "cycles": int(ci)} for (ni, ci) in zip(json_file["n"], json_file[func_name])]
                data[func_name] = x
    
    # filter keys according to inclue/exclude
    func_names = list(data.keys())
    func_names = arg_filter(func_names, include, exclude)
    tmp = []
    # tmp["n"] = data["n"]
    for fn in func_names:
        if fn == "n": continue
        tmp.append({"implementation name": fn, "data": data[fn]})
    data = tmp

    data = pd.json_normalize(
    data,
    record_path=['data'],
    meta=['implementation name'],
    errors='ignore')
    
    functions = arg_filter(functions, include, exclude)
    print("[    DATA LOADER]     loaded data for the plots {}".format(func_names))
    return functions, data

def arg_parse():
    # add argparse to specify function names that should either be included or excluded
    parser = argparse.ArgumentParser()
    parser.add_argument("-include", type=str, nargs="*", dest="include",
                        help="Only function names containing a string from this list will be included, eg. sin")
    parser.add_argument("-exclude", type=str, nargs="*", dest="exclude",
                        help="Exclude all function names that contain a string from this list, eg. cosh")
    parser.add_argument("-save",
                        type=str,
                        nargs="?",
                        dest="save",
                        const="plot.png",
                        help="Save plot output instead of showing it, default filename is plot.png")
    parser.add_argument("-builder",
                        type=str,
                        nargs="?",
                        dest="builder",
                        default="dbuild_size 8192",
                        help="Which build commant to use (build, build_size, dbuild_size or pbuild_size)")
    parser.add_argument("-runner",
                        type=str,
                        nargs="?",
                        dest="runner",
                        default="run",
                        help="Which run commant to use (run, sim)")
    args = parser.parse_args()

    return (args.include, args.exclude, args.save, args.builder, args.runner)

def arg_filter(x, include, exclude):
    x_filter = [True] * len(x)
    for i,k in enumerate(x):
        if k == "n":
            continue

        if include is not None and exclude is not None:
            if not any([inc in k for inc in include]) or any([exc in k for exc in exclude]):
                x_filter[i] = False
        elif include is not None:
            if not any([inc in k for inc in include]):
                x_filter[i] = False
        elif exclude is not None:
            if any([exc in k for exc in exclude]):
                x_filter[i] = False
    return list(compress(x, x_filter))
