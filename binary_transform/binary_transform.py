#!/usr/bin/env python

import argparse
import pefile
import os
import recipe
from capstone import *

def pe_write(pe, path):
    #pe.IMAGE_FILE_HEADER.TimeDateStamp = 
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
    pe.write(filename=path)

def get_plugins():
    plugins = {}
    plugin_dir = os.path.relpath(os.path.join(".", "plugins"))
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py"):
            modname = filename[:-3]
            plugins[modname] = getattr(__import__("plugins.%s" % modname), modname)
    return plugins

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", dest="binary_path", action="store")
    parser.add_argument("--recipe", dest="recipe_path", action="store")

    # Parse recipes
    args = parser.parse_args()

    if args.binary_path is not None and args.recipe_path is not None:
        plugins = get_plugins()

        rec = recipe.construct_recipe(args.recipe_path)
        pe = pefile.PE(args.binary_path)

        for plugin in plugins:
            if plugin in rec.recipe:
                print("> Performing binary transformation %s on %s" % (os.path.split(args.binary_path)[1], plugin))
                transform = plugins[plugin].Tranform(pe, CS_ARCH_X86, CS_MODE_64)
                transform.transform()
                transform.finalize()

        pe_write(pe, args.binary_path + ".transform")

