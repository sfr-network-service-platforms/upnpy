upnpy
=====

A fully featured UPnP python stack


interactive browser 
-------------------

Find, monitor, interact with UPnP device with the interactive browser. The interactive browser is enhanced python shell based on bpython. It requires bpython and python-urwid to work

Start the browser :

       ./upnpy/browser.py

The browser window is split in three panes :

- left pane : the bpython console itself. Have a look at http://docs.bpython-interpreter.org/
- right pane : devices & services tree
- bottom pane : logs & events

Then get a handle on a device or a service with the search (list of device) or get (single or first instance) functions. Ex:

     >>> u.search('*')
     [<Device neufbox router http://192.168.1.1:49152/rootDesc.xml>,
     <Service WANIPConnection http://192.168.1.1:49152/ctl/IPConn>,
     ...
     ]

     >>> u.search('upnp:rootdevice')
     ...
     
     
