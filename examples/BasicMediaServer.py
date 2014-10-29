#!/usr/bin/env python

"""A basic MediaServer"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import sys
sys.path += ['.']

import upnpy
from upnpy.device import BaseService, BaseDevice, StateVariable, action, ActionError, _TextElement, _getURL
from upnpy import utils

try:
    from xml.etree import cElementTree as ElementTree
except:
    from xml.etree import ElementTree
import os 

DNS = utils.Namespace('urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/', 'didl')
UNS = utils.Namespace('urn:schemas-upnp-org:metadata-1-0/upnp/', 'upnp')
DCNS = utils.Namespace('http://purl.org/dc/elements/1.1/', 'dc')

class BasicContentDirectory(BaseService):
    serviceType = 'urn:schemas-upnp-org:service:ContentDirectory:1'
    serviceId = 'urn:upnp-org:serviceId:ContentDirectory'

    A_ARG_TYPE_ObjectID = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_Result = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_BrowseFlag = StateVariable('string', sendEvents=False,
                                          allowedValue=['BrowseMetadata', 'BrowseDirectChildren'])
    A_ARG_TYPE_Filter = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_SortCriteria = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_Index = StateVariable('ui4', sendEvents=False)
    A_ARG_TYPE_Count = StateVariable('ui4', sendEvents=False)
    A_ARG_TYPE_UpdateID = StateVariable('ui4')

    @action(params = dict(ObjectID = 'A_ARG_TYPE_ObjectID',
                          BrowseFlag = 'A_ARG_TYPE_BrowseFlag',
                          Filter = 'A_ARG_TYPE_Filter',
                          StartingIndex = 'A_ARG_TYPE_Index',
                          RequestedCount = 'A_ARG_TYPE_Count',
                          SortCriteria = 'A_ARG_TYPE_SortCriteria'),
            returns = dict(Result  = 'A_ARG_TYPE_Result' ,
                           NumberReturned = 'A_ARG_TYPE_Count',
                           TotalMatches = 'A_ARG_TYPE_Count',
                           UpdateID = 'A_ARG_TYPE_UpdateID'))
    def Browse(self, _env, ObjectID='0', BrowseFlag='BrowseDirectChildren', Filter='',
               StartingIndex=0, RequestedCount=None, SortCriteria=''):

        relpath = '' if ObjectID == '0' else ObjectID
        
        fullpath = os.path.join(self.content_path, relpath)
        
        if not fullpath.startswith(self.content_path) or not os.path.exists(fullpath):
            raise ActionError(402, detail = "ObjectID %s not found" % ObjectID)
        
        didl = ElementTree.Element(DNS('DIDL-Lite'))
        ret = []

        if BrowseFlag == 'BrowseMetadata':
            meta = self._get_metadata(_env, relpath, ObjectID)
            if not meta:
                raise ActionError(402, detail = "invalid ObjectID %s" % ObjectID)
            ret.append(meta)

        elif BrowseFlag == 'BrowseDirectChildren':
            if not os.path.isdir(fullpath):
                raise ActionError(402, detail = "invalid ObjectID %s" % ObjectID)
            data = os.listdir(fullpath)
            for d in data:
                meta = self._get_metadata(_env, os.path.join(relpath, d), ObjectID)
                if meta:
                    ret.append(meta)
        else:
            raise ActionError(600, detail="BrowseFlag = %r" % BrowseFlag)

        didl.extend(ret[StartingIndex:][:RequestedCount] if RequestedCount else ret[StartingIndex:])

        return dict(Result=utils.tostring(didl, default_namespace=DNS.ns),
                    NumberReturned=len(didl), TotalMatches=len(ret), UpdateID=0)

    def _get_metadata(self, _env, relpath, parent):

        fullpath = os.path.join(self.content_path, relpath)
        oid = relpath

        if os.path.isdir(fullpath):
            o = ElementTree.Element(DNS('container'), {DNS('id'):oid, DNS('parentID'):parent, DNS('restricted'):'1'})
            o.extend([
                    _TextElement(UNS('class'), 'object.container'),
                    ])

        elif os.path.isfile(fullpath):
            import mimetypes, urllib
            mime = mimetypes.guess_type(relpath, strict=False)[0]
            if not mime:
                return
            
            mt = media_type(mime)
            if not mt:
                return
            
            o = ElementTree.Element(DNS('item'), {DNS('id'):oid, DNS('parentID'):parent, DNS('restricted'):'1'})
            o.extend([
                    _TextElement(UNS('class'), 'object.item' + ('.%sItem' % mt if mt else '')),
                    _TextElement(DNS('res'), _getURL(_env,
                                                    "content?%s" % urllib.urlencode(dict(id=oid.encode('utf-8'))),
                                                    True),
                                 {DNS('protocolInfo'):'http-get:*:%s:*' % mime})
                    ])

        else:
            return
        o.append(_TextElement(DCNS('title'), os.path.basename(relpath)))
        return o
        
    def _GET_content(self, env, start_response):

        import urlparse, upnpy.utils
        for k, v in urlparse.parse_qsl(env['QUERY_STRING']):
            if k == 'id':
                id = v
                break
        else:
            start_response(upnpy.utils.status(404), [])
            return []

        import base64, os
        relpath = id.decode('utf-8')
        fullpath = os.path.join(self.content_path, relpath)
        
        if not fullpath.startswith(self.content_path) or not os.path.isfile(fullpath):
            start_response(upnpy.utils.status(404), [])
            return []

        import mimetypes
        size = os.path.getsize(fullpath)
        headers = {'Content-Type': mimetypes.guess_type(relpath, strict=False)[0],
                   'Accept-Ranges': 'bytes'}

        range = env.get('HTTP_RANGE', None)
        if not range:
            start_response(upnpy.utils.status(200), dict(headers, **{'Content-Length' : size}).items())
            return self._file_generator(fullpath, 0, size-1)

        unit, spec = range.split('=', 1)        
        if unit != 'bytes':
            start_response(upnpy.utils.status(416), [])
            return []

        #support only one range:
        spec = spec.split(',')[0]

        start, end = spec.split('-')
        start = int(start or '0')
        end = int(end or size-1)

        if end<start:
            start_response(upnpy.utils.status(200), dict(headers, **{'Content-Length' : size}).items())
            return self._file_generator(fullpath, 0, size-1)

        if start>=size or end==0:
            start_response(upnpy.utils.status(416), [])
            return []
       
        end = max(end, size-1)


        start_response(upnpy.utils.status(206), dict(headers, **{'Content-Length' : str(1+end-start),
                                 'Content-Range' : "bytes %d-%d/%d" % (start, end, size)}).items())       
        return self._file_generator(fullpath, start, end)

    def _file_generator(self, path, start=0, end=0):
        f = file(path)
        if start:
            f.seek(start)        
        while True:
            data = f.read(min(16384, 1+end-f.tell()))
            yield data
            if not data: break

def media_type(mime):

    mime = mime.split('/')
    
    if mime[0] in ['video', 'audio', 'image']:
        return mime[0]
    elif mime == ['application', 'ogg']:
        return 'audio'    
    

class BasicMediaServer(BaseDevice):
    deviceType = 'urn:schemas-upnp-org:device:MediaServer:1'
    EXPIRY = 20
    #PROTECTION = False
    SERVICES = dict(contentDirectory=BasicContentDirectory)

    def __init__(self, content_path, *args, **kwargs):
        super(BasicMediaServer, self).__init__(*args, **kwargs)
        self.services['contentDirectory'].content_path = content_path

def main():

    import sys
    path = '.'
    if len(sys.argv)>1 and os.path.isdir(sys.argv[1]):        
        path = sys.argv[1]
    path = os.path.normpath(path)

    import logging
    logging.basicConfig(stream=sys.stderr)
    logging.root.setLevel(logging.DEBUG)

    u = upnpy.Upnpy()
    u.devices['BasicMediaServer'] = BasicMediaServer(content_path=unicode(path))
    #u.devices['BasicMediaServer'].services['contentDirectory'].A_ARG_TYPE_UpdateID = 5

    upnpy.server_forever()

if __name__ == '__main__':
    main()
