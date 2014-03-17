
"""igd client example"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import upnpy
WCDTYPE = 'urn:schemas-upnp-org:device:WANConnectionDevice:1'

def GetExternalIPAddress():    
    return upnpy.Upnpy().get(WCDTYPE).WANIPConnection.GetExternalIPAddress()['NewExternalIPAddress']

def test():
    print 'ExternalIPAddress:', GetExternalIPAddress()

if __name__ == '__main__':
    test()
