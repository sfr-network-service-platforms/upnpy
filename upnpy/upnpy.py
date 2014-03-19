
"""main upnpy module, define Upnpy : a control-point or root devices list"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

__version__ = 0.9
UPNP_VERSION = 1.1

import sys, time, select, logging

from ssdp import SSDPServer
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
        self._map = {}
        self._alarms = []
        self._idle = []
        self._stop = False
        self._looping = False

        self._descriptions= {}
        self._subscriptions = {}
        self.devices = _RootList(self)

        self._ssdp = SSDPServer(self)
        self._http = None
        self._https = None
        self._connection_manager = None

        import atexit
        atexit.register(self.clean)

    def search(self, target, timeout=5.0):
        """search for devices/services
        Returns a list of device/service when at least one matching is found
        
        Args:
          target (string) : a UPnP defined search target or "*" for all
          timeout (number, optionnal) : timeout for search (default to 5 seconds)"""        

        from control import SearchHandler
        if target == '*': target = 'ssdp:all'
        self._ssdp.msearch(target, timeout/2)
        h = SearchHandler(self, target)
        self.add_handler(h)
        if not len(h.matches) and timeout:
            start = time.time()
            self.serve_while(lambda:len(h.matches)==0 and time.time()<start+timeout)
        self.remove_handler(h)
        return h.matches

    def get(self, target, timeout=5.0):
        """search a device/service
        Returns when at least one matching devices is found

        target (string) : a UPnP defined search target or "*" for all
        timeout (number) : an optionnal timeout (default to 5 seconds)"""

        matches = self.search(target, timeout/2)
        if len(matches):
            return matches[0]
        else:
            raise KeyError("UPnP '%s' not found" % target)

    def add_handler(self, handler):
        self._ssdp.add_handler(handler)

    def remove_handler(self, handler):
        self._ssdp.remove_handler(handler)

    def serve_forever(self):

        self.serve_while(lambda:True)

    def serve_while(self, condition):

        self._looping = True

        while condition() and not self._stop:
            self.serve_once()

        self._looping = False

    def serve_once(self):


        now = time.time()
        TIMEOUT = 5.0

        timeout = TIMEOUT
        if self._alarms:
            timeout = min(max(self._alarms[0].t - now, 0), TIMEOUT)

        import asyncore
        asyncore.poll(timeout=timeout, map = self._map)

        for a in self._alarms:
            if a.t < time.time():
                self._alarms.remove(a)
                a()

        for i in self._idle:
            i()

    def http_request(self, url, method='GET', callback=None, headers=None, body=None, **kwargs):

        if not self._connection_manager:
            from http import ConnectionManager
            self._connection_manager = ConnectionManager(self)

        request = self._connection_manager.create_request(url, method, callback, headers=headers, body=body, **kwargs)

        self._connection_manager.send(request)
        
        if not self._looping or not callback:
            start = time.time()
            self.serve_while(lambda:request.response is None and time.time() < start+5.0)
            if not callback:
                from http import HTTPResponse
                return request.response or HTTPResponse(0, 'timeout')

    def stop(self):
        self.clean()
        self._stop = True

    def clean(self):
        for i in self.devices.keys():
            del self.devices[i]
            
        for i, r in self._subscriptions.items():
            d = r()
            if d:
                d.unsubscribe()
            else:
                del self._subscriptions[i]

        start = time.time()
        self.serve_while(lambda: (time.time()<start+1.0) and self._subscriptions)

        self._ssdp.clean()

        # if wait:
        #     start = time.time()
        #     import pdb
        #     self.serve_while(lambda:time.time()<start+1.0)

    def set_alarm(self, cb, duration):
        t = time.time() + duration
        i = 0
        for i, a in enumerate(self._alarms):
            if a.t>t:
                break
        a = _Alarm(cb, t)
        self._alarms.insert(i, a) 

        return id(a)

    def remove_alarm(self, _id):
        for a in self._alarms:
            if id(a) == _id:
                return self._alarms.remove(a)        

    def set_idle(self, cb):
        self._idle.append(cb)
        return id(cb)

    def remove_idle(self, _id):
        for i in self._idle:
            if id(i) == _id:
                return self._idle.remove(i)
          
class _Alarm(object):

    def __init__(self, cb, t):
        self.cb = cb
        self.t = t
    def __call__(self):
        return self.cb()

def test():
    upnpy = Upnpy()
    upnpy.serve_forever()

# Run test program when run as a script
if __name__ == '__main__':
    test()

    
    





