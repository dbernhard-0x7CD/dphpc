import argparse
import os
import json

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
    for k in func_names:
        if k == "n":
            continue

        if not all([inc in k for inc in include]) or any([exc in k for exc in exclude]):
            del data[k]
    
    print("[    DATA LOADER]     loaded data for the plots {}".format(data.keys()))
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

