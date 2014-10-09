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
        urwid.connect_signal(but, 'click', logging.error, 'pressed')
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
        self.formatter._fmt = "%(created)d %(name)s : "+ self.formatter._fmt

    def emit(self, record):
        msg = self.format(record)
        self.repl.logs.body.insert(0, urwid.Text((self.LOG_ATTR[record.levelname], msg)))

class MyURWIDRepl(bpython.URWIDRepl):

    def __init__(self, event_loop, palette, interpreter, config):

        import urwid_geventloop
        from bpython import repl
        #super(MyURWIDRepl, self).__init__(urwid_geventloop.GeventLoop(), palette, interpreter, config)
        repl.Repl.__init__(self, interpreter, config)

        self._redraw_handle = None
        self._redraw_pending = False
        self._redraw_time = 0

        self.listbox = bpython.BPythonListBox(urwid.SimpleListWalker([]))

        self.tooltip = urwid.ListBox(urwid.SimpleListWalker([]))
        self.tooltip.grid = None
        self.overlay = bpython.Tooltip(self.listbox, self.tooltip)
        self.stdout_hist = ''

        self.frame = urwid.Frame(self.overlay)

        if urwid.get_encoding_mode() == 'narrow':
            input_filter = decoding_input_filter
        else:
            input_filter = None

        # This constructs a raw_display.Screen, which nabs sys.stdin/out.
        self.main_loop = urwid.MainLoop(
            self.frame, palette,
            event_loop=urwid_geventloop.GeventLoop(), unhandled_input=self.handle_input,
            input_filter=input_filter, handle_mouse=False, screen = MyScreen())

        # String is straight from bpython.cli
        self.statusbar = bpython.Statusbar(config,
            bpython._(" <%s> Rewind  <%s> Save  <%s> Pastebin "
              " <%s> Pager  <%s> Show Source ") %
              (config.undo_key, config.save_key, config.pastebin_key,
               config.last_output_key, config.show_source_key), self.main_loop)
        self.frame.set_footer(self.statusbar.widget)
        self.interact = bpython.URWIDInteraction(self.config, self.statusbar, self.frame)

        self.edits = []
        self.edit = None
        self.current_output = None
        self._completion_update_suppressed = False

        # Bulletproof: this is a value extract_exit_value accepts.
        self.exit_value = ()

        bpython.load_urwid_command_map(config)



        logging.root.handlers=[MyLogHandler(self), logging.StreamHandler(file('/tmp/upnpy_browser.log', 'w'))]
        logging.root.setLevel(logging.INFO)
        logging.getLogger('http.access').setLevel(logging.ERROR)

        self.devices = urwid.ListBox(urwid.SimpleListWalker([urwid.Text('Devices:')]))
        self.logs = urwid.ListBox(urwid.SimpleListWalker([]))

        self.frame.set_footer(urwid.BoxAdapter(self.logs, 15))

        self.main_frame = urwid.Columns([
                self.frame,
                ('fixed', 35, self.devices),
                ])

        self.main_loop.widget = self.main_frame

        self.handler = MyDiscoverHandler(u, self)
        u.add_handler(self.handler)

bpython.URWIDRepl = MyURWIDRepl

class threadsafe_iter:
    """Takes an iterator/generator and makes it thread-safe by
    serializing call to the `next` method of given iterator/generator.
    """
    def __init__(self, it):
        self.it = it
        import threading
        self.lock = threading.Lock()

    def __iter__(self):
        return self

    def next(self):
        with self.lock:
            return self.it.next()

class MyScreen(urwid.raw_display.Screen):

    def _run_input_iter(self):
        return threadsafe_iter(urwid.raw_display.Screen._run_input_iter(self))

class Service(control.Service):

    def _set_state_value(self, name, value):
        self._logger.info("%s = %s", name, value)
        super(Service, self)._set_state_value(name, value)

class Device(control.Device):
    
    def __init__(self, *args, **kwargs):
        kwargs['service_class'] = Service
        super(Device, self).__init__(*args, **kwargs)        
        
    def _byebye(self, lost):
        super(Device, self)._byebye(lost)
        if hasattr(self, 'repl'):
            self._logger.info("byebye" + (" (lost)" if lost else ""))
            for dlb in self.repl.devices.body:
                if getattr(dlb, 'device', None) == self:
                    self.repl.devices.body.remove(dlb)

class MyDiscoverHandler(control.BaseDiscoveryHandler):

    TARGET = 'upnp:rootdevice'

    def __init__(self, upnpy, repl):
        self.repl = repl
        super(MyDiscoverHandler, self).__init__(upnpy, device_class=Device)
        upnpy.ssdp.msearch(self.TARGET, 1.0)

    def match(self, ssdp):
        #if ssdp.type == self.TARGET:
        #    self.logger.info('match %s', ssdp)
        return ssdp.type == self.TARGET

    def create(self, ssdp):
        device = super(MyDiscoverHandler, self).create(ssdp)
        device.repl = self.repl

    def handle(self, device):
        device._logger.info("alive")
        for dlb in self.repl.devices.body:
            if hasattr(dlb, 'device') and dlb.device.USN == device.USN:
                return 

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
