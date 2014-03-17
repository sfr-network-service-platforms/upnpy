#!/usr/bin/env python

"""interactive console browser"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import sys, time, select

sys.path.append('/usr/share/bpython')
try:
    import urwid_ as bpython
except ImportError, e:
    raise type(e)(e.message + " (package bpython-urwid missing)")

import urwid
import asyncore, socket
import upnpy, control

import logging
logging.basicConfig()

u = upnpy.Upnpy()

from http import LoggedDispatcher

class Watch(LoggedDispatcher, asyncore.dispatcher):

    def __init__(self, fd, callback):
        LoggedDispatcher.__init__(self)
        asyncore.dispatcher.__init__(self, map=u._map)

        self.socket = fd
        self._fileno = fd
        self.callback = callback
        self.add_channel()

    def handle_read_event(self):
        try:
            self.callback()
        except urwid.main_loop.ExitMainLoop:
            u.stop()

        #print "read"
        #raise Exception

    def handle_close(self):
        #import os
        #os.close(self._fileno)
        self.connected = False
        self.accepting = False
        self.connecting = False
        self.del_channel()

    def writable(self):
        return False

class UpnpyEventLoop(object):

    def alarm(self, seconds, callback):
        return u.set_alarm(callback, seconds)

    def remove_alarm(self, handle):
        u.remove_alarm(handle)

    def watch_file(self, fd, callback):
        # import os, logging
        # logging.error(fd)
        # logging.error(os.readlink('/proc/self/fd/%d' %fd))
        # #print os.system('ls -l /proc/self/fd/')
        # #raise Exception(fd)
        Watch(fd, callback)
        return fd

    def remove_watch_file(self, handle):
        del u._map[handle]

    def enter_idle(self, callback):
        return u.set_idle(callback)

    def remove_enter_idle(self, handle):
        u.remove_idle(handle)

    def run(self):
        u.serve_forever()
            
class DeviceListBox(urwid.BoxAdapter):

    def __init__(self, device):

        super(DeviceListBox, self).__init__(urwid.TreeListBox(urwid.TreeWalker(DeviceNode(device))),
                                            self._get_size(device))
        self.device = device

    def _get_size(self, device):
        return 1 + len(device.services) + sum(self._get_size(d) for d in device.devices.values())

class DeviceNode(urwid.ParentNode):
    """ Data storage object for interior/parent nodes """
    def load_widget(self):
        return DeviceTreeWidget(self)
    def load_child_keys(self):
        dev = self.get_value()
        return [('service', k) for k in dev.services.keys()] \
            + [('device', k) for k in dev.devices.keys()] \

    def load_child_node(self, key):
        dev = self.get_value()
        if key[0] == 'device':
            return DeviceNode(dev.devices[key[1]], parent=self, key=key)
        if key[0] == 'service':
            return ServiceNode(dev.services[key[1]], parent=self, key=key)

class ServiceNode(urwid.TreeNode):
    """ Data storage object for leaf nodes """
    def load_widget(self):
        return ServiceTreeWidget(self)

class ObjTreeWidget(urwid.TreeWidget):
    def load_inner_widget(self):
        but = urwid.Button(self.get_display_text())
        #urwid.connect_signal(but, 'click', lambda:logging.error('pressed'))
        return but

class DeviceTreeWidget(ObjTreeWidget):
    """ Display widget for leaf nodes """
    def get_display_text(self):
        device = self.get_node().get_value()
        fn = device.friendlyName
        if not fn:
            fn = device.deviceType.split(':')
            if len(fn)>3:
                fn = fn[3]
            else:
                fn = ":".join(fn)
        return ('paren', fn)

class ServiceTreeWidget(ObjTreeWidget):
    """ Display widget for leaf nodes """
    def get_display_text(self):
        service = self.get_node().get_value()
        return ('output', service._shortType)

import logging
    
class MyLogHandler(logging.Handler):
    LOG_ATTR = dict(
        DEBUG='comment',
        INFO='name',
        WARNING='operator',
        ERROR='error', 
        CRITICAL='error')

    def __init__(self, repl):
        logging.Handler.__init__(self)
        self.repl = repl
        self.setFormatter(logging.Formatter())#"%(name)s"))
        self.formatter._fmt = "%(name)s : "+ self.formatter._fmt

    def emit(self, record):
        msg = self.format(record)
        self.repl.logs.body.insert(0, urwid.Text((self.LOG_ATTR[record.levelname], msg)))

class MyURWIDRepl(bpython.URWIDRepl):

    def __init__(self, event_loop, palette, interpreter, config):

        super(MyURWIDRepl, self).__init__(UpnpyEventLoop(), palette, interpreter, config)

        logging.root.handlers=[MyLogHandler(self), logging.StreamHandler(file('/tmp/upnpy_browser.log', 'w'))]
        logging.root.setLevel(logging.INFO)
        logging.getLogger('http.access').setLevel(logging.ERROR)

        self.devices = urwid.ListBox(urwid.SimpleListWalker([urwid.Text('Devices:')]))
        self.logs = urwid.ListBox(urwid.SimpleListWalker([]))

        self.frame.set_footer(urwid.BoxAdapter(self.logs, 35))

        self.main_frame = urwid.Columns([
                self.frame,
                ('fixed', 40, self.devices),
                ])

        self.main_loop.widget = self.main_frame

        self.handler = MyDiscoverHandler(u, self)
        u.add_handler(self.handler)

bpython.URWIDRepl = MyURWIDRepl

class Service(control.Service):

    def _set_state_value(self, name, value):
        self._logger.info("%s = %s", name, value)
        super(Service, self)._set_state_value(name, value)

class Device(control.Device):
    
    def __init__(self, *args, **kwargs):
        kwargs['service_class'] = Service
        super(Device, self).__init__(*args, **kwargs)        
        
    def _byebye(self):
        if hasattr(self, 'repl'):
            self._logger.info("byebye")
            for dlb in self.repl.devices.body:
                if getattr(dlb, 'device', None) == self:
                    self.repl.devices.body.remove(dlb)
        super(Device, self)._byebye()

class MyDiscoverHandler(control.BaseDiscoveryHandler):

    TARGET = 'upnp:rootdevice'

    def __init__(self, upnpy, repl):
        self.repl = repl
        super(MyDiscoverHandler, self).__init__(upnpy, device_class=Device)
        upnpy._ssdp.msearch(self.TARGET, 2.0)

    def match(self, ssdp):
        return ssdp.type == self.TARGET

    def create(self, ssdp):
        device = super(MyDiscoverHandler, self).create(ssdp)
        device.repl = self.repl

    def handle(self, device):
        device._logger.info("alive")
        self.repl.devices.body.append(DeviceListBox(device))
        #if not hasattr(self.upnpy, devices


def main():

    #self.handler = 
    #u.add_handler(MyDiscoverHandler(None))
    #u.serve_forever()
    
    #u.serve_forever()
    bpython.main(locals_=dict(u=u))

if __name__ == '__main__':
    main()
