"""
An enum-like type with reverse lookup.

Source: Python Cookbook, http://code.activestate.com/recipes/67107/
"""


class EnumError(Exception):
    pass


class Enumeration:
    def __init__(self, name, enum_list):
        self.__doc__ = name

        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = set()
        uniqueValues = set()
        for x in enum_list:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumError(f"enum name {x} not a string")
            if not isinstance(i, int):
                raise EnumError(f"enum value {x} not an integer")
            if x in uniqueNames:
                raise EnumError(f"enum name {x} not unique")
            if i in uniqueValues:
                raise EnumError(f"enum value {x} not unique")
            uniqueNames.add(x)
            uniqueValues.add(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup

    def __getattr__(self, attr):
        result = self.lookup.get(attr)
        if result is None:
            raise AttributeError(f'enumeration has no member {attr}')
        return result

    def whatis(self, value):
        return self.reverseLookup[value]
