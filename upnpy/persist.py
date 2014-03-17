
"""persistance of data"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import shelve, os, fcntl, contextlib

PATH = os.path.expanduser('~/.cache/upnpy')
lock = file(PATH+'.lock', 'r+')

@contextlib.contextmanager
def DB(write=True):
    fcntl.flock(lock, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
    db = shelve.open(PATH, 'c', writeback=True)
    yield db
    db.close()
    fcntl.flock(lock, fcntl.LOCK_UN)


