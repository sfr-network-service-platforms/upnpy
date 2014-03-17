

"""control point classes"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import utils 

try:
    from xml.etree import cElementTree as ElementTree
except:
    from xml.etree import ElementTree
import logging

SQNS = utils.Namespace('http://schemas.xmlsoap.org/soap/envelope/', 'soap')
DNS = utils.Namespace('urn:schemas-upnp-org:device-1-0', 'device')
SNS = utils.Namespace('urn:schemas-upnp-org:service-1-0', 'service')
CNS = utils.Namespace('urn:schemas-upnp-org:control-1-0', 'control')
ENS = utils.Namespace('urn:schemas-upnp-org:event-1-0', 'event')
SES = "http://schemas.xmlsoap.org/soap/encoding/"

class UPnPObject(object):

    _DESCRIPTIONS = dict()

    def __init__(self, upnpy, location, parent=None, handler=None):

        #temporary logger replaced after object description
        self._logger = logging.getLogger(self.__class__.__name__)

        self._upnpy = upnpy
        self._handler = handler
        self._location = location
        self._parent = parent
        
    def _byebye(self):
        self._parents[0]._clean()

    def _request(self, url, command, callback, headers=None, body=None):

        self._parents[0]._conm.send_request(url, command, callback, headers, body)

    def _describe(self, location, cb):
        if location in self._DESCRIPTIONS:
            return cb(type('Response', (object,), dict(
                        body=self._DESCRIPTIONS[location],
                        code='200')))

        self._request(location, 'GET', lambda resp: self._described(location, resp, cb))

    def _described(self, location, response, cb):

        desc = response.body

        if response.code == '200' and desc:
            self._DESCRIPTIONS[location] = desc

        cb(response)

    @property
    def _parents(self):
        ret = [self]
        while ret[0]._parent:
            ret.insert(0, ret[0]._parent)
        return ret

    def __del__(self):
        self._parents[0]._clean()

class Service(UPnPObject):

    _ATTRS = ['serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL']
    EXPIRY = 300

    def __init__(self, upnpy, location, parent=None, handler=None, desc=None):
        super(Service, self).__init__(upnpy, location, parent, handler)

        self._subscription = None
        self._parse_short(desc)
        self._statevalues = {}

    def _parse_short(self, desc):

        for tag in self._ATTRS:
            n = desc.find(DNS(tag))
            setattr(self, tag, n.text if n is not None else None)

        st = self.serviceType.split(':')
        if len(st) > 3:
            st = st[3]
        elif len(st) > 1:
            st = st[1]
        else:
            st = ":".join(st)
        self._shortType = st

        self._logger = logging.getLogger('service.%s:%s' % (self._parent.friendlyName, self._shortType))

        if self.SCPDURL:
            self._describe(self._absurl(self.SCPDURL), self._parse)
            
    def _parse(self, response):

        desc = None
        if response.code != '200' or not response.body:
            self._logger.error('cannot access service description : %s %s at %s', response.code, response.status, self._absurl(self.SCPDURL))
        else:
            try:
                desc = ElementTree.ElementTree(ElementTree.fromstring(response.body))
            except Exception, e:
                self._logger.error('cannot parse service description : %s %r', str(e), response.body)

        if isinstance(desc, ElementTree.ElementTree):
            sl = desc.find(SNS('serviceStateTable'))
            if sl is not None:
                for e in sl.findall(SNS('stateVariable')):
                    a = StateVariable(self, e)
                    setattr(self, a.identifier, a)
            al = desc.find(SNS('actionList'))
            if al is not None:
                for e in al.findall(SNS('action')):
                    a = Action(self, e)                    
                    setattr(self, a.identifier, a.fct)

        if self._handler:
            self._handler(self)

        if self.eventSubURL:
            self._subscribe()

    def _do_action(self, action, _cb, args):

        self._request(self._absurl(self.controlURL), 'POST', lambda r:self._result(action, r, _cb),
                      headers = {'Content-Type': 'text/xml; charset="utf-8"',
                       'SOAPAction':'"%s#%s"' % (self.serviceType, action)},
                      body=self._soapQuery(action, args))

    def _result(self, action, response, cb):
        self._logger.debug(response.body)
        ret = self._parseSoapResponse(action, response)
        if cb:
            cb(**ret)
        else:
            self._logger.info("%s result : %r", action, ret)

    def _subscribe(self):

        if not self._subscription:
            self._subscription = Subscription(self)
        else:
            self._subscription.renew()
        
    def _unsubscribe(self):
        if self._subscription:
            self._subscription.unsubscribe()

    def _notify(self, request):
        if request.command != 'NOTIFY':
            self._logger.warning('invalid command on notification path : %s', request.command)

        if request.headers.get('SID', '') != getattr(self._subscription, 'sid', None):
            return (412,)
        
        try:
            body = request.body
            body = ElementTree.fromstring(body[body.index('<'):body.rindex('>')+1])
        except ElementTree.ParseError, e:
            self._logger.exception('Cannot parse %r', request.body)
            return (500,)

        stnse = self._stns("")

        for p in body.findall(ENS('property')):
            t = p[0]
            name = t.tag
            if name.startswith(stnse):
                name = name[len(stnse):]
            value = t.text
            if getattr(self, name, None) != value:
                self._set_state_value(name, value)            

        return (200,)

    def _set_state_value(self, name, value):
        setattr(self, name, value)

    def _soapQuery(self, action, args):

        env = ElementTree.Element(SQNS('Enveloppe'), {SQNS('encodingStyle'):SES})
        act = ElementTree.SubElement(ElementTree.SubElement(env,SQNS('Body')), self._stns(action))
        
        for k, v in args.iteritems():
            e = ElementTree.SubElement(act, self._stns(k))
            if v is not None:
                e.text=str(v)
            
        return utils.tostring(env, encoding='utf-8', default_namespace=self._stns.ns)

    def _parseSoapResponse(self, action, response):

        ret = {}
        
        body = ElementTree.fromstring(response.body).find(SQNS('Body'))
        response = body.find(self._stns(action+'Response'))
        if response is None:
            desc = body.find(SQNS('Fault/')+SQNS('detail/')+CNS('UPnPError/')+CNS('errorDescription'))
            if desc is not None:
                raise ActionError(desc.text)
            fs = body.find(SQNS('Fault/')+SQNS('faultstring'))
            if fs is not None:
                raise ActionError(fs.text)
            raise ActionError()

        stnse = self._stns("")

        for e in list(response):
            name = e.tag
            value = e.text
            if name.startswith(stnse):
                name = name[len(stnse):]
            ret[name] = value
        
        return ret

    @property
    def USN(self):
        return "%s::%s" % (self._parent.UDN, self.serviceType)

    @property
    def _type(self):
        return self.serviceType

    @property
    def _stns(self):
        if not hasattr(self, '__stns'):
            self.__stns = utils.Namespace(self.serviceType)
        return self.__stns

    def _match(self, ssdp):
        return ssdp.usn == self.USN

    def _absurl(self, url):
        if url.startswith('http://') or url.startswith('https://'):
            return url
        elif url.startswith('/'):
            return '/'.join(self._location.split('/')[:3])+url
        else:
            return self._location.rsplit('/',1)[0]+'/'+url

    def __repr__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self._shortType, self._absurl(self.controlURL or self.SCPDURL))

    def __del__(self):
        if self._subscription:
            self._unsubscribe()
        super(Service, self).__del__()

class Argument(object):
    def __init__(self, service, name, related):
        self.name = name
        self.identifier = utils.normalize(name)
        self.related = related
        self.state_variable = getattr(service, related, None)

    def doc(self):
        return "%s : %s (%s%s)" % (
            self.identifier,
            getattr(self.state_variable, 'dataType', '?'),
            self.related,
            ", real argument name : %s" % self.name if self.identifier != self.name else "",
            )

class Action(object):

    def __init__(self, service, desc):
                
        self.service = service
        self.name, params, returns = self.parse(desc)

        self.identifier = utils.normalize(self.name)
        self.logger = service._logger.getChild(self.name)

        self.params = dict(params)
        self.returns = dict(returns)

        self.fct = self.generate_fct_signature([p[1] for p in params], [r[1] for r in returns])

    def parse(self, desc):
        name = desc.find(SNS('name')).text

        params = []
        returns = []
        args = desc.find(SNS('argumentList'))
        if args:
            for a in args:
                n = a.find(SNS('name')).text
                r = a.find(SNS('relatedStateVariable')).text
                d = a.find(SNS('direction')).text
                {'in':params, 'out':returns}[d].append(
                    (n, Argument(self.service, n, r)))
                        

        return (name, params, returns)

    def generate_fct_signature(self, params, returns):
        
        definition = '''
def %s(%s):
    """Method %s.%s
params:
  %s
returns:
  %s
"""
    self.do_action({%s}, _cb=_cb)
        ''' % (
            utils.normalize(self.name),
            ", ".join(["%s=None" % p.identifier for p in params]+['_cb=None']),
            self.service._shortType,
            self.name,
            "\n  ".join(p.doc() for p in params) if params else None,
            "\n  ".join(r.doc() for r in returns) if returns else None,
            ", ".join("'%s':%s" % (p.name, p.identifier) for p in params)
            )

        self.logger.debug("definition : %s", definition)

        loc = dict(self=self)#locals()
        try:
            exec(definition, loc)#, dict())
        except SyntaxError, e:
            self.logger.exception("cannot generate function : %s" % definition)
            return
        return loc[self.name]

    def do_action(self, args, _cb):

        for k, v in args.items():
            if v is None:
                del args[k]
        for k, a in self.params.items():
            if k in args and args[k] is not None and a.state_variable:
                args[k] = a.state_variable.serialize(args[k])

        return self.service._do_action(self.name, _cb, args)

class ActionError(Exception):
    pass

class StateVariable(utils.StateVariable):

    def __init__(self, service, desc):

        self.service = service
        self.parse(desc)

    def parse(self, desc):

        self.name = desc.find(SNS('name')).text
        self.identifier = utils.normalize(self.name)

        self.sendEvents = desc.get(SNS('sendEvents'), True)
        self.multicast = desc.get(SNS('multicast'), False)

        t = desc.find(SNS('dataType'))
        self.dataType = t.text
        self.extendType = t.get(SNS('type'), None)
        self.default = desc.find(SNS('defaultValue')).text if desc.find(SNS('defaultValue')) is not None else None
        if desc.find(SNS('allowedValueList')) is not None:
            self.allowedValue = []
            for v in desc.find(SNS('allowedValueList')).findall(SNS('allowedValue')):
                self.allowedValue.append(v.text)
        elif desc.find(SNS('allowedValueRange')) is not None:
            e = desc.find(SNS('allowedValueRange'))
            self.allowedValue = dict([(k, e.find(SNS(k)).text) for k in ['minimum', 'maximum', 'step'] if e.find(SNS(k)) is not None])
        else:
            self.allowedValue = None

    def __get__(self, obj, objtype=None):
        if obj == None:
            return self
        elif self in obj._statevalues:
            return obj._statevalues[self]
        elif self.default is not None:
            return self.default
        raise AttributeError("state variable not set")

    def __set__(self, obj, value):
        obj._statevalues[self], old = value, get(obj._statevalues, self, None)

class Subscription(object):
    
    def __init__(self, service):
        self.service = service
        self.conm = self.service._parents[0]._conm
        self.sid = None
        self.alarm = None
        self.upnpy = service._upnpy

        self.subscribe()
    
    def subscribe(self):

        if not self.upnpy._http:
            from http import HTTPServer
            self.upnpy._http = HTTPServer(self.upnpy)

        headers = dict(TIMEOUT='Second-%d'%self.service.EXPIRY)

        request = self.conm.create_request(self.service._absurl(self.service.eventSubURL),
                                                                'SUBSCRIBE', headers=headers)
        request.callback = self._subscribed

        if self.sid:
            headers['SID'] = self.sid
        else:
            headers['NT'] = 'upnp:event'
            def on_connect(conn):
                headers['CALLBACK'] = "<http://%s:%d/_notification>" % \
                    (conn.getsockname()[0],
                     self.upnpy._http.server_port)
            request.on_connect = on_connect

        self.conm.send(request)

    def _subscribed(self, response):
        if response.code != '200':
            if self.sid:
                self.sid = None
                return self.subscribe()
            return self.service._logger.warning('subscription error : %s %s', response.code, response.status)
        
        self.sid = response.headers.get('SID', self.sid or None)
        if self.sid is None:
            return self.service._logger.warning('subscription error : no SID')

        import weakref
        self.upnpy._subscriptions[self.sid] = weakref.ref(self)

        expiry = int(response.headers.get('TIMEOUT', '-%d' % self.service.EXPIRY).split('-')[1])
        self.alarm = self.upnpy.set_alarm(self.renew, expiry/2)

    def renew(self):
        self.subscribe()

    def unsubscribe(self):
        self.service._upnpy.remove_alarm(self.alarm)
        self.service._request(self.service._absurl(self.service.eventSubURL), 'UNSUBSCRIBE', self._unsubscribed,
        headers=dict(SID=self.sid))        

        self.service._subscription = None        

    def _unsubscribed(self, response):
        pass

    def notify(self, request):
        return self.service._notify(request)    

class Device(UPnPObject):

    _ATTRS = ['deviceType', 'friendlyName', 'manufacturer', 'manufacturerURL', 'modelDescription',
            'modelName', 'modelNumber', 'modelURL', 'serialNumber', 'UDN', 'UPC', 'presentationURL']
    
    def __init__(self, upnpy, location, parent=None, desc=None, handler=None, service_class=None, device_class=None):
        super(Device, self).__init__(upnpy, location, parent, handler)

        self._service_class = service_class or Service
        self._device_class = device_class or self.__class__
        
        self.services = {}
        self.devices = {}

        from http import ConnectionManager
        self._conm = None if parent else ConnectionManager(upnpy)

        if desc:
            self._parse(desc)
        else:
            self._describe(location,
                           self._parse)

    def _parse(self, description):

        desc = None

        if hasattr(description, 'makeelement'): #check if Element
            desc = description
        elif description.code != '200' or not description.body:
            self._logger.error('cannot access device description : %s %s at %s', description.code, description.status, self._location)
        else:
            try:
                desc = ElementTree.ElementTree(ElementTree.fromstring(description.body)).find(DNS('device'))
            except Exception, e:
                self._logger.error('cannot parse device description : %s %r', str(e), description.body)

        if desc is None:
            return

        for tag in self._ATTRS:
            n = desc.find(DNS(tag))            
            setattr(self, tag, getattr(n, 'text', None))
            
        self._logger = logging.getLogger('device.%s' % (self.friendlyName,))
            
        for d in desc.findall(DNS('deviceList/')+DNS('device')):
            device = self._device_class(self._upnpy, self._location, parent=self, desc=d, handler=self._handler)
            self.devices[device.deviceType] = device
            if len(device.deviceType.split(':')) <= 3:
                continue            
            short = device.deviceType.split(':')[3]
            if not hasattr(self, short):
                setattr(self, short, device)
                
        for s in desc.findall(DNS('serviceList/')+DNS('service')):
            service = self._service_class(self._upnpy, self._location, parent=self, desc=s, handler=self._handler)            
            self.services[service.serviceType] = service

            if not hasattr(self, service._shortType):
                setattr(self, service._shortType, service)

        if self._handler:
            self._handler(self)        
               
    @property
    def USN(self):
        return "%s::%s" % (self.UDN, self.deviceType)

    @property
    def _type(self):
        return self.deviceType

    def _match(self, ssdp):
        return (ssdp.type == 'upnp:rootdevice' and not self._parent) \
            or ssdp.usn == self.USN \
            or ssdp.usn == self.UDN

    def __repr__(self):
        fn = self.friendlyName
        if isinstance(fn, unicode):
            fn = utils.unormalize(fn)
        return "<%s %s %s>" % (self.__class__.__name__, fn, self._location)

    def _clean(self):
        if self._conm:
            self._conm.clean()

class BaseDiscoveryHandler(object):

    def __init__(self, upnpy, device_class=Device):
        self.device_class = device_class
        self.upnpy = upnpy
        
    def match(self, ssdp):
        return True

    def create(self, ssdp):
        return self.device_class(self.upnpy, ssdp.seclocation or ssdp.location,
                                 handler=lambda o:self._created(o, ssdp))

    def _created(self, obj, ssdp):
        if obj._match(ssdp):
            import weakref
            ssdp.devices.append(weakref.ref(obj))
            self.handle(obj)

    def handle(self, obj):
        print obj

class SearchHandler(BaseDiscoveryHandler):

    def __init__(self, upnpy, target, *args, **kwargs):
        super(SearchHandler, self).__init__(upnpy, *args,**kwargs)
        self.target = target
        self.matches = []

    def match(self, ssdp):
        #logging.info('match %s ? %s', self.target, ssdp)
        if self.target in ['ssdp:all',
                         ssdp.type,
                         ssdp.usn]:
            return True

    def handle(self, devser):
        if devser.USN not in map(lambda o:o.USN, self.matches):
            self.matches.append(devser)
