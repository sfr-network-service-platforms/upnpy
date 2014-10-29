
"""main upnpy module, define Upnpy : a control-point or root devices list"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

__version__ = 0.9
UPNP_VERSION = 1.1

import sys, time, select, logging
import gevent, gevent.monkey
gevent.monkey.patch_all()

from device import _RootList

class Upnpy(object):
    """A upnpy controller working either as a control-point or as devices root list
    Can be used to search remote device (get, search)
    Can be used to declare new devices devices['example']=Device(...)
    """

    def __init__(self, server_address=''):
        """Initialize Upnpy
        server_address (tring) : an optionnal address to bind connection to"""

        self.server_address = server_address

        import weakref
        self._subscriptions = weakref.WeakValueDictionary()
        self.devices = _RootList(self)

        self._stop = False
        import atexit
        atexit.register(self.clean)

    def __getattr__(self, attr):
        if attr is 'ssdp':
            from ssdp import SSDPServer
            self.ssdp = SSDPServer(self)
            return self.ssdp

        elif attr is 'http':
            from http import HTTPServer
            self.http = HTTPServer(self)
            return self.http

        elif attr is 'https':
            from http import HTTPServer
            self.https = HTTPServer(self, True)
            return self.https

        else:
            raise AttributeError("'%s' has no attribute %r" %
                                 (self.__class__.__name__, attr))


    def search(self, target, timeout=2.0):
        """search for devices/services
        Returns a list of device/service when at least one matching is found
        
        Args:
          target (string) : a UPnP defined search target :
            - ssdp:all (or *) : for all devices and services
            - upnp:rootdevice : for all root devices
            - uuid:[uuid]     : for a particular device
            - [urn:domain:]{device,service}:type[:version] : for a device or service with the given type
                                domain default to schemas-upnp-org,
                                version to 1

          timeout (number, optionnal) : timeout for search (default to 5 seconds)"""        

        from control import SearchHandler
        h = SearchHandler(self, target, timeout)
        self.add_handler(h)
        if not len(h.matches) and timeout:
            gevent.sleep(timeout)
        return h.matches

    def get(self, target, timeout=2.0):
        """search a device/service
        Returns when at least one matching devices is found

        target (string) : a UPnP defined search target or "*" for ssdp:all
        timeout (number) : an optionnal timeout (default to 5 seconds)"""

        matches = self.search(target, timeout/2)
        if len(matches):
            return matches[0]
        else:
            raise KeyError("UPnP '%s' not found" % target)

    def serve_forever(self):
        gevent.wait()


    def add_handler(self, handler):
        self.ssdp.add_handler(handler)

    def stop(self):
        self.clean()
        self._stop = True

    def clean(self):
        for i in self.devices.keys():
            del self.devices[i]
            
        for s in self._subscriptions.values():
            s.unsubscribe()

        self.ssdp.clean()

        # if wait:
        #     start = time.time()
        #     import pdb
        #     self.serve_while(lambda:time.time()<start+1.0)
          

def test():
    upnpy = Upnpy()
    upnpy.serve_forever()

# Run test program when run as a script
if __name__ == '__main__':
    test()

    
    





