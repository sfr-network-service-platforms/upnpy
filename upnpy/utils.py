
"""utility functions used throughout upnpy"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

try:
    from xml.etree import cElementTree as ElementTree
except:
    from xml.etree import ElementTree

class Namespace(object):
    """a namespace helper, a la xml.etree.ElementTree.QName, with theses added features:
    - the namespace is registered if a prefix is given
    - the namespace name is available through 'ns' property"""

    def __init__(self, ns, prefix=None):
        """Args:
          ns (string) - namespace
          prefix (string) - optionnal prefix to register"""
        self.ns = ns
        if prefix:
            ElementTree.register_namespace(prefix, ns)

    def __call__(self, tag):
        return "{%s}%s" % (self.ns, tag)

def tostring(etree, *args, **kwargs):
    """Generates a string representation of an XML element
    support all xml.etree.ElementTree.ElementTree.write arguments."""

    if hasattr(etree, 'makeelement'): #check if Element => change as ElementTree to get .write
        etree = ElementTree.ElementTree(etree)

    try:
        import cStringIO as StringIO
    except:
        import StringIO as StringIO

    ret = StringIO.StringIO()
    etree.write(ret, *args, **kwargs)
    return ret.getvalue()

def unormalize(ustring):
    """normalize a unicode string to ascii"""
    import unicodedata
    return unicodedata.normalize('NFKD', ustring).encode('ascii', 'ignore')
    
def genUUID():
    """generate a new random UUID"""
    import uuid
    return 'uuid:%s' % uuid.uuid4()

class StateVariable(object):
    """base for state variable supporting data parsing/serializatino"""
    
    def parse(self, val):
        """parse a string and cast it depending on its dataType"""

        dt = self.dataType
        if dt in ['ui1', 'ui2', 'ui4', 'i1', 'i2', 'i4', 'int']:
            return int(val)
        elif dt in ['r4', 'r8', 'number', 'fixed.14.4', 'float']:
            return float(val)
        elif dt == 'bin.base64':
            return val.decode('base64')
        elif dt == 'bin.hex':
            return val.decode('hex')
        elif dt == 'boolean':
            try:
                return bool(int(val))
            except ValueError:
                val = val.lower()
                if 'true'.startswith(val) or 'yes'.startswith(val):
                    return True
                elif 'false'.startswith(val) or 'no'.startswith(val):
                    return False
                raise
        return val

    def serialize(self, val):
        """serialize a value depending on its dataType"""

        dt = self.dataType
        if dt == 'boolean':
            return str(int(val))
        elif dt == 'bin.base64':
            return val.encode('base64')
        elif dt == 'bin.hex':
            return val.encode('hex')
        return str(val)

import re, tokenize, keyword
RIDENTIFIER = re.compile(tokenize.Name)
def normalize(name):
    """normalize a string to the best next python identifier"""

    name = "_".join(RIDENTIFIER.findall(name))

    if keyword.iskeyword(name):
        name = name.capitalize()

    return name
