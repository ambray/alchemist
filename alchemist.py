#!/usr/bin/env python

import clang.cindex
import sys
clang.cindex.Config.set_library_path("/Library/Developer/CommandLineTools/usr/lib")

def parser(path):
    index = clang.cindex.Index.create()
    return index.parse(path, ['-x', 'c++'])



if __name__ == '__main__':
    pass