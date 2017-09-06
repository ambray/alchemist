#!/usr/bin/env python

import clang.cindex
import argparse
import sys
import os

from mako.template import Template
from clang.cindex import TypeKind
from clang.cindex import StorageClass
from clang.cindex import CursorKind
from fragments import *

if sys.platform == 'darwin':
    clang.cindex.Config.set_library_path("/Library/Developer/CommandLineTools/usr/lib")

storage_class_mapping = {
    StorageClass.NONE: "",
    StorageClass.STATIC: "static ",
    StorageClass.EXTERN: "extern ",
}

platform_identifier = (
    'Win32',
    'Linux',
    'OSX',
)

glue_lang = (
    "c",
    "c++",
)


class CodeEmitter(object):

    def __get_fragments(self, glue_language):
        if self.platform == 'Win32' and glue_language == "c":
            self.fragments = win32_c
        else:
            raise RuntimeError("[x] Unsupported platform!")

    def __init__(self, platform, glue_language="c"):
        self.platform = platform
        if glue_language not in glue_lang:
            raise RuntimeError("[x] Invalid glue language requested! Valid options: {}".format(", ".join(glue_lang)))

        self.__get_fragments(glue_language)

    def emit(self, btype, *args):
        frag = self.fragments.get(btype, None)
        if frag is None:
            raise RuntimeError("[x] Invalid fragment type selected!")



class CodeGenRegistrar(type):
    def __init__(cls, name, bases, dct):
        if not hasattr(cls, 'plugins'):
            cls.plugins = {}
        else:
            cls.plugins[name.lower()] = cls

        super(CodeGenRegistrar, cls).__init__(name, bases, dct)


class CodeGenBaseObject(object):
    __metaclass__ = CodeGenRegistrar

    def __init__(self, platform_id, emitter=None):
        if platform_id not in platform_identifier:
            raise RuntimeError("[x] Invalid platform specified! Please pick one of the following: {}".format(
                ", ".join(platform_identifier)))

        self.platform = platform_id
        self.code_emit = emitter if emitter is not None else CodeEmitter(platform_id)

    def transform(self, p):
        pass

    def emit(self, block_type):
        pass


class CodeGenBaseImpl(CodeGenBaseObject):
    def __init__(self, platform):
        super(CodeGenBaseImpl, self).__init__(platform)

    def transform(self, p):
        pass

    def execute(self, cursor):
        """
        Executes the transform method on each plugin, providing the cursor to each
        :param cursor:
        :return:
        """
        for plugin in self.plugins.keys():
            tmp = self.plugins[plugin]()
            tmp.transform(cursor)


class Function(object):
    """
    An object wrapping a clang cursor pointer to a function.
    Provides helper methods to generate glue code - function signature creation,
    interface for marshaling code generator, etc
    """

    # TODO: Handle edge cases - variadic and template methods, member functions, static
    # and const/constexpr methods, calling conventions, alternate function syntax methods
    def get_signature(self):
        return "{}{} {}".format(
            storage_class_mapping.get(self.cursor.storage_class, ""),
            self.cursor.type.get_result().spelling,
            self.cursor.displayname)

    def __init__(self, node):
        if not isinstance(node, clang.cindex.Cursor) or not node.type.kind == TypeKind.FUNCTIONPROTO:
            raise RuntimeError("[x] Invalid node type presented!")

        self.cursor = node
        self.name = node.spelling


#TODO: Handle namespaces
def extract_tokens_from_file(path,
                             node_filter=lambda x, p: True if x.location.file.name == p else False,
                             args=('-x', 'c++')):
    """
    Retrieves all of the top-level tokens belonging to the file provided as "path"
    :param path: Path to the file to parse
    :param node_filter: Method taking a node and a path, should return true if this node is to be kept, false otherwise
    :param args: Args to pass to clang during the parsing of the file
    :return: Generator of filtered nodes
    """
    idx = clang.cindex.Index.create()
    tu = idx.parse(path, args)

    for node in tu.cursor.get_children():
        if node_filter(node, path):
            yield node


def method_has_attr(node, attr_text):
    """
    Checks to see if the given method starts with annotation text, e.g. __attribute__((annotate(<attr_text>)))
    :param node: The function to check
    :param attr_text: The tag which the annotation text should start with
    :return: Bool indicating whether the method has the attribute or not
    """
    if not isinstance(node, clang.cindex.Cursor) or not node.type.kind == TypeKind.FUNCTIONPROTO:
        return False

    for ctok in node.get_children():
        if ctok.kind == CursorKind.ANNOTATE_ATTR and ctok.spelling.startswith(attr_text):
            return True

    return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", dest="path", action="store")

    args = parser.parse_args()

    funcs = dict()
    toks = extract_tokens_from_file(args.path)
    for token in toks:
        if token.type.kind == TypeKind.FUNCTIONPROTO:
            funcs[token.spelling] = Function(token)

    for func in funcs.keys():
        print("{}".format(funcs[func].get_signature()))

