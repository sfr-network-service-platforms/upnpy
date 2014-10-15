

"""control point classes"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import utils 
import urlparse, http
import gevent

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

STATE_DISCOVERED="discovered"
STATE_READY="ready"
STATE_BYEBYE="byebye"

class UPnPObject(object):

    def __init__(self, upnpy, location):

        #temporary logger replaced after object description
        self._logger = logging.getLogger(self.__class__.__name__)
        self._state = STATE_DISCOVERED 

        self._upnpy = upnpy
        self._location = location

    def _byebye(self, lost):
        self._state = STATE_BYEBYE

    def _request(self, url, method, *args, **kwargs):

        req = http.HTTPRequest(url)
        up = urlparse.urlparse(url)
        req.request(method, urlparse.urlunparse(('','')+up[2:]), *args, **kwargs)
        return req.getresponse(True)

    def _describe(self, url):
        return http.describe(url)

class Service(UPnPObject):

    _ATTRS = ['serviceType', 'serviceId', 'SCPDURL', 'controlURL', 'eventSubURL']

    def __init__(self, upnpy, location, desc, parent, handler=None):
        super(Service, self).__init__(upnpy, location)

        self._subscription = None
        self._parse_short(desc)
        self.UDN = parent.UDN
        self._statevalues = {}
        self._state = STATE_READY

        self._logger = logging.getLogger('service.%s:%s' % (parent.friendlyName, self._shortType))

        if handler:
            handler(self)

        if self.SCPDURL:
            try:
                self._parse(self._describe(self._absurl(self.SCPDURL)))
            except Exception, e:
                self._logger.error('cannot access service description : %s at %s', e, self._absurl(self.SCPDURL))

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
           
    def _parse(self, response):

        desc = None
        if response.status != 200 or not response.body:
            self._logger.error('cannot access service description : %d %s at %s', response.status, response.reason, self._absurl(self.SCPDURL))
        else:
            try:
                desc = ElementTree.ElementTree(ElementTree.fromstring(response.body))
            except Exception, e:
                self._logger.error('cannot parse service description : %s %r', str(e), response.body)

        if isinstance(desc, ElementTree.ElementTree):
            sl = desc.find(SNS('serviceStateTable'))
            if sl is not None:
                for e in sl.findall(SNS('stateVariable')):
                    a = StateVariable(e)
                    setattr(self, a.identifier, a)
            al = desc.find(SNS('actionList'))
            if al is not None:
                for e in al.findall(SNS('action')):
                    a = Action(self, e)                    
                    setattr(self, a.identifier, a.fct)

        if self.eventSubURL:
            self._subscribe()

    def _byebye(self, lost):
        super(Service, self)._byebye(lost)
        self._subscription = None
        self._statevalues = {}

    def _action(self, action, args):
        
        if self._state != STATE_READY:
            raise ActionError("Service is not ready (state=%s)" % self._state)
       
        import socket
        try:
            return self._action_result(action, 
                                       self._request(self._absurl(self.controlURL), 'POST',
                                                     headers = {'Content-Type': 'text/xml; charset="utf-8"',
                                                                'SOAPAction':'"%s#%s"' % (self.serviceType, action)},
                                                     body=self._soapQuery(action, args)))
        except socket.error, e:
            raise ActionError("Socket error %s", str(e).decode('latin9'))
        except Exception, e:
            raise ActionError("Unknown error %s", e)

    def _action_result(self, action, response):        
        response.body = response.read()
        self._logger.debug(response.body)
        ret = self._parseSoapResponse(action, response)
        return ret

    def _subscribe(self):

        if not self._subscription:
            self._subscription = Subscription(self)
        else:
            self._subscription.renew()
        
    def _unsubscribe(self):
        if self._subscription:
            self._subscription.unsubscribe()

    def _notify(self, env, start_response):
        if env['REQUEST_METHOD'] != 'NOTIFY':
            self._logger.warning('invalid method on notification path : %s', env['REQUEST_METHOD'])

        if env.get('HTTP_SID', '') != getattr(self._subscription, 'sid', None):
            start_response(utils.status(412), [])
            return []
        
        try:
            body = env['wsgi.input'].read()
            body = ElementTree.fromstring(body[body.index('<'):body.rindex('>')+1])
        except ElementTree.ParseError, e:
            self._logger.exception('Cannot parse %r', body)
            start_response(utils.status(500), [])
            return []

        stnse = self._stns("")

        for p in body.findall(ENS('property')):
            t = p[0]
            name = t.tag
            if name.startswith(stnse):
                name = name[len(stnse):]
            value = t.text
            if getattr(self, name, None) != value:
                self._set_state_value(name, value)            

        start_response(utils.status(200), [])
        return []


    def _set_state_value(self, name, value):
        setattr(self, name, value)

    def _soapQuery(self, action, args):

        env = ElementTree.Element(SQNS('Envelope'), {SQNS('encodingStyle'):SES})
        act = ElementTree.SubElement(ElementTree.SubElement(env,SQNS('Body')), self._stns(action))
        
        for k, v in args.iteritems():
            e = ElementTree.SubElement(act, self._stns(k))
            if v is not None:
                e.text=str(v)
            
        return utils.tostring(env, encoding='utf-8', xml_declaration=True)
        #default_namespace=SQNS.ns)
        #does not seem to behave correctly with some xml library (libupnp, ..)

    def _parseSoapResponse(self, action, response):

        ret = {}

        if response.body is None:
            raise ActionError('HTTP body not found (http : %d %s)', response.status, response.reason)        

        body = ElementTree.fromstring(response.body).find(SQNS('Body'))
        if body is None:
            raise ActionError('Soap body not found')

        action_response = body.find(self._stns(action+'Response'))
        if action_response is None and body.find(SQNS('Fault')) is None and len(list(body))>0:
            action_response = list(body)[0]
            self._logger.warning("spurious response node tag '%s'", action_response.tag)       

        if action_response is None:
            
            fault = body.find(SQNS('Fault'))
            if fault is None:              
                raise ActionError('No response found')

            desc = fault.find(SQNS('detail/')+CNS('UPnPError/')+CNS('errorDescription'))
            if desc is not None:
                raise ActionError(desc.text)

            fs = fault.find(SQNS('faultstring'))
            if fs is not None:
                raise ActionError(fs.text)

            raise ActionError("Unknown error (http : %d %s)", response.status, response.body)

        stnse = self._stns("")

        for e in list(action_response):
            name = e.tag
            value = e.text
            if name.startswith(stnse):
                name = name[len(stnse):]
            ret[name] = value
        
        return ret

    @property
    def USN(self):
        return "%s::%s" % (self.UDN, self.serviceType)

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
    return self.do_action({%s})
        ''' % (
            utils.normalize(self.name),
            ", ".join(["%s=None" % p.identifier for p in params]),
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

    def do_action(self, args):

        for k, v in args.items():
            if v is None:
                del args[k]
        for k, a in self.params.items():
            if k in args and args[k] is not None and a.state_variable:
                args[k] = a.state_variable.serialize(args[k])

        ret = self.service._action(self.name, args)

        for k, a in self.returns.items():
            ret[k] = a.state_variable.parse(ret[k])

        return ret

class ActionError(Exception):
    pass

class StateVariable(utils.StateVariable):

    def __init__(self, desc):

        self.parse_desc(desc)

    def parse_desc(self, desc):

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
    
    EXPIRY = 100

    def __init__(self, service):
        import weakref
        self.service = weakref.proxy(service, self.unsubscribe)
        self.url = service._absurl(service.eventSubURL)
        self.sid = None
        self.alarm = None
        self.upnpy = service._upnpy

        self.subscribe()
    
    def subscribe(self):

        headers = dict(TIMEOUT='Second-%d'%self.EXPIRY)
        if self.sid:
            headers['SID'] = self.sid
        else:
            headers['NT'] = 'upnp:event'

        req = http.HTTPRequest(self.url)
        if not self.sid:
            req.connect()
            headers['CALLBACK'] = "<http://%s:%d/_notification>" % \
                (req.sock.getsockname()[0],
                 self.upnpy.http.server_port)       
                   
        up = urlparse.urlparse(self.url)
        req.request('SUBSCRIBE',
                    urlparse.urlunparse(('','')+up[2:]),
                    headers=headers)
        self._subscribed(req.getresponse())

    def _subscribed(self, response):
        if response.status != 200:
            if self.sid:
                self.sid = None
                return self.subscribe()
            return self.service._logger.warning('subscription error : %d %s', response.status, response.reason)
        
        self.sid = response.getheader('SID', self.sid)
        if self.sid is None:
            return self.service._logger.warning('subscription error : no SID')

        self.upnpy._subscriptions[self.sid] = self

        expiry = int(response.getheader('TIMEOUT', '-%d' % self.EXPIRY).split('-')[1])
        if self.alarm and self.alarm != gevent.getcurrent():
            self.alarm.kill()

        self.alarm = gevent.spawn_later(expiry/2, self.renew, True)

    def renew(self, auto=False):
        try:
            self.subscribe()
        except:
            if not auto:
                raise

    def unsubscribe(self, arg=None):
        if self.alarm:
            self.alarm.kill()

        self.upnpy._subscriptions.pop(self.sid, None)

        import socket
        try:            
            req = http.HTTPRequest(self.url)
            up = urlparse.urlparse(self.url)
            req.request('UNSUBSCRIBE',
                        urlparse.urlunparse(('','')+up[2:]),
                        headers=dict(SID=self.sid))
            self._unsubscribed(req.getresponse())

        except socket.error:
            pass

        self.sid = None

        try:
            self.service._subscription = None        
        except ReferenceError:
            pass

    def _unsubscribed(self, response):
        pass

    def notify(self, env, start_response):
        try:
            return self.service._notify(env, start_response)    
        except ReferenceError:
            start_response(utils.status(404), [])
            return []

class Device(UPnPObject):

    _ATTRS = ['deviceType', 'friendlyName', 'manufacturer', 'manufacturerURL', 'modelDescription',
            'modelName', 'modelNumber', 'modelURL', 'serialNumber', 'UDN', 'UPC', 'presentationURL']
    
    def __init__(self, upnpy, location, parent=None, desc=None, handler=None, service_class=None, device_class=None):
        super(Device, self).__init__(upnpy, location)

        self._service_class = service_class or Service
        self._device_class = device_class or self.__class__
        
        self.services = {}
        self.devices = {}

        self._root = parent is None

        self._parse(desc or self._describe(self._location), handler)

        self._state = STATE_READY

        if handler:
            handler(self)

    def _parse(self, description, handler):

        desc = None

        if hasattr(description, 'makeelement'): #check if Element
            desc = description
        elif description.status != 200 or not description.body:
            self._logger.error('cannot access device description : %d %s at %s', description.status, description.reason, self._location)
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
            device = self._device_class(self._upnpy, self._location, parent=self, desc=d, handler=handler)
            self.devices[device.deviceType] = device
            if len(device.deviceType.split(':')) <= 3:
                continue            
            short = device.deviceType.split(':')[3]
            if not hasattr(self, short):
                setattr(self, short, device)
                
        for s in desc.findall(DNS('serviceList/')+DNS('service')):
            service = self._service_class(self._upnpy, self._location, desc=s, parent=self, handler=handler)            
            self.services[service.serviceType] = service

            if not hasattr(self, service._shortType):
                setattr(self, service._shortType, service)
               
    @property
    def USN(self):
        return "%s::%s" % (self.UDN, self.deviceType)

    @property
    def _type(self):
        return self.deviceType

    def _match(self, ssdp):
        return ( ssdp.usn == self.USN
                     or ( ssdp.usn == self.UDN and self._root) #some subdevices share UDN with parent
                     or ( ssdp.usn == ('%s::upnp:rootdevice' % self.UDN) and self._root))

    def __repr__(self):
        try:
            fn = self.friendlyName
            if isinstance(fn, unicode):
                fn = utils.unormalize(fn)
        except AttributeError:
            fn="unknown device"
        return "<%s %s %s>" % (self.__class__.__name__, fn, self._location)

class BaseDiscoveryHandler(object):

    def __init__(self, upnpy, device_class=Device):
        self.device_class = device_class
        self.upnpy = upnpy
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def match(self, ssdp):
        return True

    def create(self, ssdp):
        errors = dict()
        for l in list(ssdp.headers.get('SECURELOCATION.UPNP.ORG', [])) + list(ssdp.headers['LOCATION']):
            import socket
            try:
                return self.device_class(self.upnpy, l, 
                                         handler=lambda o:self._created(o, ssdp))
            except socket.error, e:
                errors[l] = e
                self.logger.error("%s for description at %s", e, l)
            #except Exception, e:
            #    errors[l] = e
            #    self.logger.exception("%s for description at %s", e, l)

        raise LookupError(", ".join("%s => %s" % le for le in errors.items()))

    def _created(self, obj, ssdp):

        for e in self.upnpy.ssdp._seen.values():
            if obj._match(e):
                e.devices.add(obj)

        if obj._match(ssdp):
            self.handle(obj)

    def handle(self, obj):
        print obj

class SearchHandler(BaseDiscoveryHandler):

    def __init__(self, upnpy, target, timeout=5.0, *args, **kwargs):
        super(SearchHandler, self).__init__(upnpy, *args,**kwargs)        
        
        if target == '*':
            target = 'ssdp:all'
        elif target.split(':')[0] not in ['ssdp', 'upnp', 'uuid']:
            target = target.split(':')
            if target[0] != 'urn':
                target = ['urn', 'schemas-upnp-org'] + target
            if len(target) == 4:
                target += ['1']
            target = ":".join(target)

        self.target = target
        self.matches = []
        self.upnpy.ssdp.msearch(self.target, timeout/2.0)

    def match(self, ssdp):
        #logging.info('match %s ? %s', self.target, ssdp)
        if self.target in ['ssdp:all',
                           ssdp.type,
                           ssdp.usn]:
            return True

    def handle(self, devser):
        if devser.USN not in map(lambda o:o.USN, self.matches):
            self.matches.append(devser)
