#!/usr/bin/env python

import clang.cindex
import itertools
import argparse
import random
import string
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

marshal_types = (
    "bytes",
    "word",
    "dword",
    "qword",
    "float",
    "bool",
)

param_annotations = (
    "out",
    "out-dealloc",
    "map",
)


class Command(object):
    """
    Class to manage and track command data.
    """

    def controller_unmarshal_task_results(self, marshal):
        pass

    def controller_marshal_task(self, marshal):
        pass

    def client_unmarshal_task(self, marshal):
        pass

    def client_marshal_task_results(self, marshal):
        pass

    def __init__(self, name, entry_point, in_data, out_data):
        """
        :param name:  Human-friendly name for the command
        :param entry_point: Entry point; should be a Function(...)
        :param in_data: Key-value pairs of id/data type for task data from controller -> agent
        :param out_data:  Key-value pairs of id/data type for task data from agent -> controller
        """
        self.name = name
        self.entry = entry_point
        self.id = random.getrandbits(32)
        self.in_values = (type(k, (),
                                {'name': k, 'id': random.getrandbits(32), 'type': in_data.get(k)}) for k in in_data.keys())
        self.out_values = (type(k, (),
                                {'name': k, 'id': random.getrandbits(32), 'type': out_data.get(k)}) for k in out_data.keys())


class MarshalBase(object):

    def __validate(self):
        for val in marshal_types:
            if self.methods.get(val, None) is None:
                raise RuntimeError("[x] Missing marshaling method: {} must be implemented!".format(val))

    def __add_if_unmarshal(self, tok):
        is_valid, msg = method_has_attr(tok, "unmarshal")
        if not is_valid:
            return False

        mt = msg.split(" ")
        if len(mt) < 2:
            raise RuntimeError("[x] Invalid annotation on unmarshal method! Must provide a type, e.g.: bytes")

        if mt[1] not in marshal_types:
            raise RuntimeError("[x] Invalid unmarshal type! Must be one of the following: {}".format(", ".join(marshal_types)))
        self.unmarshal_methods[mt[1]] = Function(tok)
        return True

    def __add_if_marshal(self, tok):
        is_valid, msg = method_has_attr(tok, "marshal")
        if not is_valid:
            return False

        mtype = msg.split(" ")
        if len(mtype) < 2:
            raise RuntimeError("[x] Invalid annotation on marshal method! Must provide a type, e.g.: bytes")

        if mtype[1] not in marshal_types:
            raise RuntimeError("[x] Improperly formatted marshaling method! Received {}, Must select one of these values: {}".format(
                    mtype[1],
                    ", ".join(marshal_types)
                ))

        self.methods[mtype[1]] = Function(tok)
        return True

    def __init__(self, file_path, args=None, errors=None):
        self.methods = {}
        self.unmarshal_methods = {}
        if not os.path.isfile(file_path):
            raise RuntimeError("[x] Failed to find requested file for marshaler! {}".format(file_path))

        for tok in extract_tokens_from_file(file_path, include_paths=() if args is None else args, print_diags=errors):
            if not self.__add_if_marshal(tok) or not self.__add_if_unmarshal(tok):
                continue

        self.__validate()

    def get_controller(self):
        pass

    def get_agent_unpack(self):
        pass

    def get_agent_pack(self):
        pass


class CommsBase(object):

    def __init__(self, file_path):
        if not os.path.isfile(file_path):
            raise RuntimeError("[x] Failed to find requested file for comms! {}".format(file_path))

    def build_controller(self):
        pass

    def build_send(self):
        pass

    def build_recv(self):
        pass


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


class WinCodeGenBaseImpl(CodeGenBaseObject):

    def __get_symbol_name(self, count=random.randint(5, 15)):
        """
        Produces a symbol with a unique name (for the current file, at least)
        :param count: Number of characters for the symbol, will default to a random value from 5-15
        :return: The generated symbol name
        """
        while True:
            sym = random.sample(string.ascii_letters + string.digits, count)
            if sym not in self.sym_list:
                self.sym_list.add(sym)
                return sym

    def __init__(self, platform):
        super(WinCodeGenBaseImpl, self).__init__(platform)
        self.sym_list = set()
        self.entry_decl = None
        self.entry_template = """
        ${entry_decl}
        {
            ${entry_code}
        
            return ${return_value}; 
        }
        
        """

    def begin_entry(self, entry_params):
        """
        Begins the generation of the entry point
        :param entry_params: Dictionary; contains: type (DllMain, main, WinMain), platform (windows)
        :return:
        """
        entry_type = entry_params.get("type", "main")

        self.entry_decl = windows_entry_points.get(entry_type, None)
        if self.entry_decl is None:
            raise RuntimeError("[x] Invalid entry point type specified! Must be: {}".format(
                ", ".join(windows_entry_points.keys())))

        event_entry = entry_params.get("event_loop_type", "timer")


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


class Param(object):
    """
    A wrapper for a function parameter. It includes parsed semantic information from annotations.
    """

    def __parse_annotations(self):
        for annotation in self.annotations:
            val = annotation.split(" ")
            if val[0] == "out":
                self.out_param = True
            elif val[0] == "out-dealloc":
                self.dealloc = val[2]
                self.out_param = True
            elif val[0] == "map":
                self.mapped_symbol = val[1]
            else:
                continue

    def get_type(self):
        """
        :return: Returns the string representation of the underlying param type
        """
        return self.cursor.type.spelling

    def get_param_name(self):
        """
        :return:  Returns the name of the parameter
        """
        return self.cursor.spelling

    def get_typekind(self):
        """
        :return:  Retrieves the TypeKind value of the param
        """
        return self.cursor.type.kind

    def get_deref_type(self):
        """
        :return: If the type is a pointer, gets the pointed-to type
        """
        if self.cursor.type.kind != TypeKind.POINTER:
            raise RuntimeError("[x] Can't get the pointee of a non-pointer type!")

        return self.cursor.type.get_pointee()

    def get_deref_decl(self):
        """
        :return: If the type is a pointer, gets the string representation
                 of the pointed-to type
        """
        return self.get_deref_type().spelling

    def __repr__(self):
        return "<Param {} : Type - {}, Method Position - {}>".format(self.cursor.spelling, self.cursor.type.spelling,
                                        self.position, ", ".join(self.annotations))

    def __init__(self, cursor, annotations, position):
        """
        :param cursor:  The cursor pointing to the argument in question
        :param annotations:  Annotation that relate to this particular parameter
        :param position:  The position (from 1..n) in the function the argument appears at
        """
        self.out_param = False
        self.dealloc = None
        self.mapped_symbol = None
        self.cursor = cursor
        self.annotations = annotations
        self.position = position
        self.__parse_annotations()


class Function(object):
    """
    An object wrapping a clang cursor pointer to a function.
    Provides helper methods to generate glue code - function signature creation,
    interface for marshaling code generator, etc
    """

    def __repr__(self):
        return "[Function: (name: {}), (proto: {}), (fails if: {}), params: {}]".format(
            self.cursor.spelling, self.get_signature(),
            ", ".join(["<{} {}>".format(k, self.fail_if.get(k)) for k in self.fail_if.keys()]),
            ", ".join([str(param) for param in self.params])
        )

    def __extract_param_annotations(self, token):
        relevant = []
        for annotation in self.annotations:
            if annotation.find(token.spelling) != -1:
                relevant.append(annotation)

        return relevant

    def __extract_method_annotations(self):
        for annotation in self.annotations:
            if annotation.startswith("fail-if"):
                tmp = annotation.split(" ")
                if len(tmp) < 3:
                    raise RuntimeError("[x] Invalid failure case provided!")
                self.fail_if[tmp[1]] = tmp[2]

    def __get_params(self):
        res = []
        i = 0
        for tok in self.cursor.get_arguments():
            res.append(Param(tok, self.__extract_param_annotations(tok), i))
            i += 1

        return res

    def get_failure_check_info(self, case):
        """
        :param case:  Failure case to check for. Eventually will be "throws" or "return", but only return is
                      currently supported.
        :return:  The value to check for, or None if not provided
        """
        return self.fail_if.get(case, None)

    def get_annotations(self):
        res = []
        for tok in self.cursor.get_children():
            if tok.kind == CursorKind.ANNOTATE_ATTR:
                res.append(tok.spelling)

        return res

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
        self.fail_if = dict()
        self.name = node.spelling
        self.annotations = self.get_annotations()
        self.__extract_method_annotations()
        self.params = self.__get_params()


def __extract_diag_strings(diag_iter):
    res = []
    for diag in diag_iter:
        res.append(str(diag))

    return "\n".join(res)


#TODO: Handle namespaces
def extract_tokens_from_file(path, include_paths=(),
                             node_filter=lambda x, p: True if x.location.file.name == p else False,
                             args=('-x', 'c++'), print_diags=False):
    """
    Retrieves all of the top-level tokens belonging to the file provided as "path"
    :param path: Path to the file to parse
    :param node_filter: Method taking a node and a path, should return true if this node is to be kept, false otherwise
    :param args: Args to pass to clang during the parsing of the file
    :return: Generator of filtered nodes
    """
    fin_args = []
    for arg in args:
        fin_args.append(arg)

    if not isinstance(include_paths, str) and not isinstance(include_paths, unicode):
        for inc in include_paths:
            fin_args.append("-I{}".format(inc))
    else:
        fin_args.append("-I{}".format(include_paths))

    idx = clang.cindex.Index.create()
    tu = idx.parse(path, fin_args)

    if tu.diagnostics is not None and print_diags:
        print("[x] Compiler errors/warnings occurred!\n{}".format(__extract_diag_strings(tu.diagnostics)))

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
    if not isinstance(node, clang.cindex.Cursor) or node.type.kind != TypeKind.FUNCTIONPROTO:
        return False, None

    for ctok in node.get_children():
        print("{}".format(ctok.spelling))
        if ctok.kind == CursorKind.ANNOTATE_ATTR and ctok.spelling.startswith(attr_text):
            return True, ctok.spelling

    return False, None


def test():
    common_includes_path = os.path.relpath(os.path.join(".", "source", "common_includes"))
    toks = extract_tokens_from_file(os.path.join(".", "source", "capabilities", "windows", "get_file", "get_file.c"), args=("-x", "c++", "-I{}".format(common_includes_path)))
    return toks

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", dest="path", action="store")
    parser.add_argument("--marshal", dest="marshal", action="store")
    parser.add_argument("--print-errors", dest="errors", action="store_true")
    common_includes_path = os.path.relpath(os.path.join(os.path.split(__file__)[0], "source", "common_includes"))
    print("Includes: {}".format(common_includes_path))

    args = parser.parse_args()
    if args.path is not None:
        funcs = dict()
        toks = extract_tokens_from_file(args.path, include_paths=common_includes_path, print_diags=args.errors)
        for token in toks:
            if token.type.kind == TypeKind.FUNCTIONPROTO:
                funcs[token.spelling] = Function(token)

        for func in funcs.keys():
            print("{}".format(funcs[func]))
    if args.marshal is not None:
        marsh = MarshalBase(args.marshal, args=common_includes_path, errors=args.errors)
        for k in marsh.methods.keys():
            print("{} - {}".format(k, marsh.methods.get(k)))



