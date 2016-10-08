# enum-like type
# From the Python Cookbook from http://code.activestate.com/recipes/67107/


class EnumException(Exception):
    pass


class Enumeration:

    def __init__(self, name, enumList):
        self.__doc__ = name

        lookup = {}
        reverseLookup = {}
        i = 0
        uniqueNames = set()
        uniqueValues = set()
        for x in enumList:
            if isinstance(x, tuple):
                x, i = x
            if not isinstance(x, str):
                raise EnumException("enum name {} not a string".format(x))
            if not isinstance(i, int):
                raise EnumException("enum value {} not an integer".format(i))
            if x in uniqueNames:
                raise EnumException("enum name {} not unique".format(x))
            if i in uniqueValues:
                raise EnumException("enum value {} not unique".format(x))
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
            raise AttributeError('enumeration has no member {}'.format(attr))
        return result

    def whatis(self, value):
        return self.reverseLookup[value]
