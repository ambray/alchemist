#!/usr/bin/env python

import yaml
import os

HERE = os.path.dirname(__file__)
schema_root = os.path.join(HERE, "schemas")


def __load_schema(schema_name):
    fname = os.path.join(schema_root, schema_name)
    if not os.path.isfile(fname):
        raise RuntimeError("[x] Schema requested: {} does not exist at path {}!".format(schema_name, fname))

    with open(fname, 'r') as f:
        return yaml.load(f.read())


def __import_recipe_data(path):
    with open(path, 'r') as f:
        return yaml.load(f.read())


def validate_and_merge(recipe, schema):
    pass


def construct_recipe(path):
    if not os.path.isfile(path):
        raise RuntimeError("[x] Invalid path requested for recipe! {} does not exist!".format(path))

    tmp = __import_recipe_data(path)

    schema_requested = tmp.get("type", None)
    if schema_requested is None:
        raise RuntimeError("[x] Attribute 'type' is missing! Must specify a type to create!")

    schema = __load_schema(schema_requested)
    res = validate_and_merge(tmp, schema)

    return type(tmp.get("name", "recipe"), (), res)



