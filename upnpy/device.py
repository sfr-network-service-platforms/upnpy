
"""device and service defintion"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import time
import logging 

try:
    from xml.etree import cElementTree as ElementTree
except:
    from xml.etree import ElementTree

import utils
import http, urlparse
from wsgiref.util import shift_path_info, guess_scheme

SQNS = utils.Namespace('http://schemas.xmlsoap.org/soap/envelope/', 'soap')
DNS = utils.Namespace('urn:schemas-upnp-org:device-1-0', 'device')
SNS = utils.Namespace('urn:schemas-upnp-org:service-1-0', 'service')
CNS = utils.Namespace('urn:schemas-upnp-org:control-1-0', 'control')
ENS = utils.Namespace('urn:schemas-upnp-org:event-1-0', 'event')
SES = "http://schemas.xmlsoap.org/soap/encoding/"

class BaseUPnPObject(object):

    EXPIRY = 1800

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            if k not in self._ATTRS:
                raise TypeError('Unknown attribute %s' % k)
            setattr(self, k, v)

    def _dispatch(self, env, start_response):

        part = shift_path_info(env)
        
        method = getattr(self, '_%s_%s' % (env['REQUEST_METHOD'], part.replace('.','_')), None)
        if len(env['PATH_INFO'].split('/')) == 1 and method:
            return method(env, start_response)
           
        start_response(utils.status(404), [])
        return []

    @property
    def _parents(self):
        ret = [self]
        while ret[0]._parent:
            ret.insert(0, ret[0]._parent)
        return ret

    @property
    def _location(self):
        return "/%s/desc.xml" % self._parents[0]._id

    @property
    def _path(self):
        return "/".join(['']+map(lambda o:o._id, self._parents)+[''])
    
    @property
    def _protection(self):        
        for obj in reversed(self._parents):
            ret = getattr(obj, 'services', {}).get('_protection', None)
            if ret:
                return ret

    def __getattr__(self, attr):
        if attr in self._ATTRS:
            return None

        elif attr == '_logger':
            if hasattr(self, 'friendlyName'):
                self._logger = logging.getLogger('device.%s' % (self.friendlyName,))
            else:
                self._logger = logging.getLogger('service.%s:%s' % (self._parent.friendlyName, self._shortType))
            return self._logger

        else:
            raise AttributeError("'%s' has no attribute %r" %
                                 (self.__class__.__name__, attr))

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, " ".join("%s=%s" % (k, getattr(self, k)) for k in self._ATTRS if hasattr(self, k)))

class BaseDevice(BaseUPnPObject):    

    PROTECTION = True
    
    _ATTRS = ['deviceType', 'friendlyName', 'manufacturer', 'manufacturerURL', 'modelDescription',
             'modelName', 'modelNumber', 'modelURL', 'serialNumber', 'UDN', 'UPC', 'presentationURL']

    def __init__(self, *args, **kwargs):
        super(BaseDevice, self).__init__(*args, **kwargs) 
        self.icons = []
        self.devices = _SubList(self)
        self.services = _SubList(self)
        if hasattr(self, 'SERVICES'):
            for i, S in self.SERVICES.items():
                self.services[i] = S()
        if hasattr(self, 'DEVICES'):
            for i, D in self.DEVICES.items():
                self.devices[i] = D()

    def _dispatch(self, env, start_response):

        if len(env['PATH_INFO'].split('/'))>2:
            part = shift_path_info(env)

            if part in self.services:
                return self.services[part]._dispatch(env, start_response)

            elif part in self.devices:
                return self.devices[part]._dispatch(env, start_response)

            start_response(utils.status(404), [])
            return []

        return super(BaseDevice, self)._dispatch(env, start_response)

    def __getattr__(self, attr):
        if attr == 'UDN':
            from persist import DB
            with DB() as db:
                try:
                    self.UDN = db['udn.%s' % self._id]
                except KeyError:
                    self.UDN = db['udn.%s' % self._id] = utils.genUUID()
            return self.UDN
        elif attr == 'friendlyName':
            self.friendlyName = self._id
            return self.friendlyName
        return super(BaseDevice, self).__getattr__(attr)

    @property
    def USN(self):
        return "%s::%s" % (self.UDN, self.deviceType)

    @property
    def _type(self):
        return self.deviceType

    def _find(self, udn, id=None, type=None):
        if self.UDN == udn:
            if (id is None and type is None) or self.deviceType == type:
                return self
            for s in self.services.values():
                if s.serviceType == type or s.serviceId == id:
                    return s
        for d in self.devices.values():
            ret = d._find(udn, id, type)
            if ret:
                return ret

    def _GET_desc_xml(self, env, start_response):

        dev = ElementTree.Element(DNS('device'))

        for a in self._ATTRS:
            dev.append(_TextElement(DNS(a), getattr(self, a)))

        if self.icons:
            ico = ElementTree.SubElement(dev, DNS('iconList'))
            #for i in self.icons

        if self.services:
            servs = ElementTree.SubElement(dev, DNS('serviceList'))            
            for name, s in self.services.items():
                servs.append(s._short_desc())

        if self.devices:
            devs = ElementTree.SubElement(dev, DNS('deviceList'))
            for name, d in self.devices.items():
                devs.append(s._GET_desc_xml(env, start_response))
        
        if self._parent:
            return dev

        root = ElementTree.Element(DNS('root'))

        from upnpy import UPNP_VERSION
        ElementTree.SubElement(root, DNS('specVersion')).extend([
                _TextElement(DNS('major'), str(UPNP_VERSION).split('.')[0]),
                _TextElement(DNS('minor'), str(UPNP_VERSION).split('.')[1])
                ])

        root.append(dev)

        start_response(utils.status(200), [('Content-Type', 'text/xml')])
        return [utils.tostring(root, default_namespace=DNS.ns)]

class BaseService(BaseUPnPObject):
    _ATTRS = ['serviceType', 'serviceId']

    def __init__(self, *args, **kwargs):
        super(BaseService, self).__init__(*args, **kwargs) 
        self._subscription = dict()
        self._statevalues = dict()

    @property
    def _type(self):
        return self.serviceType

    @property
    def _stns(self):
        if not hasattr(self, '__stns'):
            self.__stns = utils.Namespace(self.serviceType)
        return self.__stns

    @property
    def USN(self):
        return "%s::%s" % (self._parent.UDN, self.serviceType)

    def _GET_desc_xml(self, env, start_response):
        
        scpd = ElementTree.Element(SNS('scpd'))

        from upnpy import UPNP_VERSION
        ElementTree.SubElement(scpd, SNS('specVersion')).extend([
                _TextElement(SNS('major'), str(UPNP_VERSION).split('.')[0]),
                _TextElement(SNS('minor'), str(UPNP_VERSION).split('.')[1])
                ])

        cls = self.__class__
        ElementTree.SubElement(scpd, SNS('actionList')).extend([
                getattr(cls, n).desc(n) for n in dir(cls) if isinstance(getattr(cls, n), Action)
                ])
            

        ElementTree.SubElement(scpd, SNS('serviceStateTable')).extend([
                getattr(cls, n).desc(n) for n in dir(cls) if isinstance(getattr(cls, n), StateVariable)
                ])

        start_response(utils.status(200), [('Content-Type', 'text/xml')])
        return [utils.tostring(scpd, default_namespace=SNS.ns)]


    def _POST_control(self, env, start_response):
        
        body = ElementTree.fromstring(env['wsgi.input'].read()).find(SQNS('Body/*'))

        stnse = self._stns("")

        env['upnp.action'] = action = body.tag[len(stnse):]
        env['upnp.args'] = args = dict()
        for e in list(body):
            name = e.tag
            value = e.text
            if value is None:
                value = ''
            if name.startswith(stnse):
                name = name[len(stnse):]
            args[name] = value
            
        method = getattr(self, action, None)

        try:
            if not method or not isinstance(method, Action):
                self._logger.error("invalid action : %s %s", body.tag, stnse)
                raise ActionError(401, detail = action)
            return self._send_response(env, start_response, self._do_action(env, method))

        except ActionError, e:
            return self._send_error(env, start_response, e)

    def _do_action(self, env, method):
        try:
            return method(self, env)
        except ActionError, e:
            raise
        except Exception, e:
            import traceback, sys
            traceback.print_exc()
            raise ActionError(501, detail = str(e))

    def _send_response(self, env, start_response, response):
       
        envelope = ElementTree.Element(SQNS('Envelope'), {SQNS('encodingStyle'):SES})

        ElementTree.SubElement(
            ElementTree.SubElement(envelope,SQNS('Body')),
            self._stns('%sResponse'%env['upnp.action'])).extend([
                _TextElement(self._stns(k), v) for k, v in response.items()
                ])
        start_response(utils.status(200), [('Content-Type', 'text/xml')])
        return [utils.tostring(envelope, default_namespace=SQNS.ns)]
    
    def _send_error(self, env, start_response, error):
        
        envelope = ElementTree.Element(SQNS('Envelope'), {SQNS('encodingStyle'):SES})
        
        desc = ", ".join(filter(lambda p:p, [error.description, error.detail]))
        err = ElementTree.Element(CNS('UPnPError'))
        err.extend([
                _TextElement(CNS('errorCode'), str(error.code)),
                _TextElement(CNS('errorDescription'), desc)
                ])
        detail = ElementTree.Element(SQNS('detail'))
        detail.append(err)

        fault = ElementTree.SubElement(ElementTree.SubElement(envelope,SQNS('Body')), SQNS('Fault'))
        fault.extend([
                _TextElement(SQNS('faultCode'), 'Client'),
                _TextElement(SQNS('faultString'), 'UPnPError'),
                detail,
                ])
  
        start_response(utils.status(500), [('Content-Type', 'text/xml')])
        return [utils.tostring(envelope, default_namespace=SQNS.ns)]

    def _SUBSCRIBE_event(self, env, start_response):

        #force header connection: close pour bug gupnp
        headers = []
        if 'GUPnP' in env.get('HTTP_USER_AGENT', ''):
            headers.append(('Connection', 'close'))

        try:
            timeout = int(env.get('HTTP_TIMEOUT').split('-')[1])
        except:
            timeout = self.EXPIRY

        callback = env.get('HTTP_CALLBACK', None)
        sid = env.get('HTTP_SID', None)

        if callback:
            if sid:
                start_response(utils.status(400), headers)
                return []
            sub = _Subscription(self, callback.strip('<>'), timeout)
            self._subscription[sub.sid] = sub
            
            msg = self._notification_message()
            if msg:
                import gevent
                gevent.spawn_later(1, sub.notify, msg)

            headers += [('SID', sub.sid), ('TIMEOUT', 'Second-%d' % timeout)]
            start_response(utils.status(200), headers)
            return []

        elif sid:
            if callback:
                start_response(utils.status(400), headers)
                return []
            try:
                self._subscription[sid].renew(timeout)
                headers.append(('TIMEOUT','Second-%d' % timeout))
                start_response(utils.status(200), headers)
                return []
            except KeyError:
                pass

        start_response(utils.status(412), headers)
        return []

    def _UNSUBSCRIBE_event(self, env, start_response):
        try:
            del self._subscription[env.get('HTTP_SID')]
            start_response(utils.status(200), [])
            return []
        except KeyError:
            start_response(utils.status(412), [])
            return []

    def _notify(self, keys):

        now = time.time()
        msg = self._notification_message(keys)    
        for s in self._subscription.values():
            if s.timeout < now:
                del self._subscription[s]
                continue
            s.notify(msg)

    def _notification_message(self, keys=None):

        if keys is None:
            keys = []
            cls = self.__class__
            for k in dir(self):
                try:
                    if not isinstance(getattr(cls, k), StateVariable): continue
                    if getattr(self, k, None) is None: continue
                    keys.append(k)
                except AttributeError:
                    pass
        if not keys:
            return

        pset = ElementTree.Element(ENS('propertyset'))
        for k in keys:
            ElementTree.SubElement(
                ElementTree.SubElement(pset, ENS('property')),
                self._stns(k)).text = str(getattr(self, k))
        
        return utils.tostring(pset, encoding='utf-8', default_namespace=self._stns.ns)

    def _short_desc(self):
        ser = ElementTree.Element(DNS('service'))

        for a in self._ATTRS:
            ser.append(_TextElement(DNS(a), getattr(self, a)))

        base = self._path
        ser.extend([
                _TextElement(DNS('SCPDURL'), '%sdesc.xml' % base),
                _TextElement(DNS('controlURL'), '%scontrol' % base),
                _TextElement(DNS('eventSubURL'), '%sevent' % base),
                ])

        return ser

    @property
    def _shortType(self):
        return self.serviceType.split(':')[3]

def action(*args, **kwargs):
    
    def decorator(fct):
        
        return Action(fct, *args, **kwargs)

    return decorator

class Action(object):

    def __init__(self, fct, params=None, returns=None):
        self.fct = fct
        self.params = params or dict()
        self.returns = returns or dict()

        import inspect
        self.spec = inspect.getargspec(fct)

    def __call__(self, service, env):

        pt = service._protection
        if pt:
            import protection
            pt._check_acl(env, service, self)

        for k, v in env['upnp.args'].items():
            sv = getattr(service.__class__, self.params[k], None)
            if not isinstance(sv, StateVariable): continue
            try:
                env['upnp.args'][k] = sv.parse(v)
            except Exception, e:
                raise ActionError(402, detail = str(e))
            
        if "_env" in self.spec.args:
            env['upnp.args']['_env'] = env
            
        missing = []
        for a in self.spec.args[1:len(self.spec.args or [])-len(self.spec.defaults or [])]:
            if a not in env['upnp.args']:
                missing.append(a)
        if missing:
            raise ActionError(402, detail="missing argument(%s) %s" % ("s" if len(missing)>2 else "" , ", ".join(missing)))
        
        ret = self.fct(service, **env['upnp.args'])

        if ret is None:
            ret = dict()
        if not isinstance(ret, dict) and len(self.returns) == 1:
            ret = {self.returns.keys()[0]:ret}

        for k in ret.keys():
            self.returns[k]

        cls = service.__class__
        for k in self.returns.keys():
            if k not in ret or ret[k] is None: continue
            sv = getattr(cls, self.returns[k], None)
            if not isinstance(sv, StateVariable): continue
            ret[k] = sv.serialize(ret[k])

        return ret            

    def desc(self, name):
        ret = ElementTree.Element(SNS('action'))
        ElementTree.SubElement(ret, SNS('name')).text = name
        args = ElementTree.SubElement(ret, SNS('argumentList'))
        
        arguments = [(n,'in', r) for n,r in self.params.items()]
        #sort params with signature
        arguments.sort(key=lambda a:self.spec.args.index(a[0]) if a[0] in self.spec.args else len(self.spec.args))
        arguments += [(n,'out', r) for n,r in self.returns.items()]

        for n, d, r in arguments:
            ElementTree.SubElement(args, SNS('argument')).extend([
                    _TextElement(SNS('name'), n),
                    _TextElement(SNS('direction'), d),
                    _TextElement(SNS('relatedStateVariable'), r)
                    ])
        return ret        
        
class StateVariable(utils.StateVariable):

    def __init__(self, dataType, extendedType = None,
                 default=None, allowedValue = None,
                 sendEvents=True, multicast=False):

        self.dataType = dataType
        self.extendedType = extendedType
        self.default=default
        self.allowedValue = allowedValue
        self.sendEvents = sendEvents
        self.multicast = multicast


    def __get__(self, obj, objtype=None):
        if obj == None:
            return self
        elif self in obj._statevalues:
            return obj._statevalues[self]
        elif self.default is not None:
            return self.default
        raise AttributeError("state variable not set")

    def __set__(self, obj, value):
        obj._statevalues[self], old = value, obj._statevalues.get(self, None)
        if old != value and self.sendEvents:
            obj._notify([self._name(obj)])

    def __delete__(self, obj):
        if not self.default:
            raise AttributeError("state variable has no default")
        self.__set__(obj, self.default)

    def _name(self, obj):
        for n in dir(obj):
            if getattr(obj.__class__, n, None) == self:
                return n

    def desc(self, name):
        attr = dict()
        if not self.sendEvents: attr['sendEvents'] = False
        if self.multicast: attr['multicast'] = True
        ret = ElementTree.Element(SNS('stateVariable'),
                                  **dict((SNS(k), ['no', 'yes'][getattr(self, k)]) for k in ['sendEvents', 'multicast']))

        ret.extend([
                _TextElement(SNS('name'), name),
                _TextElement(SNS('dataType'), self.dataType,
                             **dict([(SNS('type'), self.extendedType)] if self.extendedType else []))
                ])
        if self.default is not None:
            ret.append(_TextElement(SND+'defaultValue', self.default))
        if isinstance(self.allowedValue, list):
            ElementTree.SubElement(ret, SNS('allowedValueList')).extend([
                    _TextElement(SNS('allowedValue'), v) for v in self.allowedValue
                    ])
        elif isinstance(self.allowedValue, dict):
            ElementTree.SubElement(ret, SNS('allowedValueRange')).extend([
                    _TextElement(SNS(k), str(self.allowedValue[k])) for k in ['minimum', 'maximum', 'step'] if k in self.allowedValue
                    ])            

        return ret

class _Subscription(object):

    def __init__(self, service, callback, timeout):
        self.service = service
        self.upnpy = service._parents[0]._upnpy
        self.callback = callback
        self.sid = utils.genUUID()
        self.seq = 0
                                                 
        self.renew(timeout)

    def renew(self, timeout):
        self.missed = 0
        self.timeout = timeout+time.time()

    def notify(self, message):
        
        req = http.HTTPRequest(self.callback)
        up = urlparse.urlparse(self.callback)
        headers = { 'NT' : 'upnp:event',
                    'NTS': 'upnp:propchange',
                    'SID': self.sid,
                    'SEQ': self.seq,
                    'CONTENT-TYPE': 'text/xml; charset="utf-8"'}
        
        try:
            req.request('NOTIFY', urlparse.urlunparse(('','')+up[2:]), message, headers)
            res = req.getresponse(True)
            if res.status != 200:
                raise Exception('http error in sending notification %d %s' % (res.status, res.reason))

        except Exception, e:            
            self.service._logger.error('error in sending notification %s', e)
            self.missed += 1
            if self.missed > 2:
                del self.service._subscription[self.sid]

        self.seq += 1
    
class _SubList(dict):

    def __init__(self, parent):
        self.parent = parent

    def __setitem__(self, i, sub):

        sub._parent = self.parent
        sub._id = i
        dict.__setitem__(self, i, sub)
        
class _RootList(dict):

    def __init__(self, upnpy):
        self.upnpy = upnpy

    def __setitem__(self, i, device, location=None, seclocation=None):

        device._parent = None
        device._upnpy = self.upnpy
        device._id = i

        dict.__setitem__(self, i, device)

        self._add_device(device)

    def _add_device(self, device):

        if device.PROTECTION and not device._protection:
            import protection
            device.services['_protection'] = protection.Service()

        if not self.upnpy.http:
            from http import HTTPServer
            self.upnpy.http = HTTPServer(self.upnpy)

        if not self.upnpy.https and device._protection:
            from http import HTTPServer
            self.upnpy.https = HTTPServer(self.upnpy, ssl=True)

        self.upnpy.ssdp.advertise(device)

        for i, s in device.services.items():
            self.upnpy.ssdp.advertise(s)

        for i, d in device.devices.items():
            self._add_device(d)

    def __delitem__(self, i):

        device = self.get(i)
        dict.__delitem__(self, i)
        
        self._del_device(device)

        if not len(self):
            self.upnpy.http = None
            self.upnpy.https = None

    def _del_device(self, device):

        self.upnpy.ssdp.withdraw(device)

        for i, s in device.services.items():
            self.upnpy.ssdp.withdraw(s)

        for i, d in device.devices.items():
            self._del_device(d)

class ActionError(Exception):
    def __init__(self, code, description = None, detail = None):
        self.code = code
        self.description = description or _ERR_DESC.get(int(code),None)
        self.detail = detail

_ERR_DESC = {
    401 : 'Invalid Action', #No action by that name at this service.
    402 : 'Invalid Args', #Could be any of the following: not enough in args, args in the wrong order, one or more in args are of the wrong data type.
    #403 : 'Invalid Credentials', #(This code has been deprecated.)
    501 : 'Action Failed', #MAY be returned if current state of service prevents invoking that action.
    600 : 'Argument Value Invalid', #The argument value is invalid
    601 : 'Argument Value Out of Range', #An argument value is less than the minimum or more than the maximum value of the allowed value range, or is not in the allowed value list.
    602 : 'Optional Action Not Implemented', #The requested action is optional and is not implemented by the device.
    603 : 'Out of Memory', 
    #The device does not have sufficient memory available to complete the action.
    #This MAY be a temporary condition; the control point MAY choose to retry the
    #unmodified request again later and it MAY succeed if memory is available.
    604 : 'Human Intervention Required', #The device has encountered an error condition which it cannot resolve itself
    #and required human intervention such as a reset or power cycle. See the device
    #display or documentation for further guidance.
    605 : 'String Argument Too Long', #A string argument is too long for the device to handle properly.
    606 : 'Action not authorized', #assigned roles don't match action requirements
    }

def _TextElement(tag, text, attrib={}, **extra):
    ret = ElementTree.Element(tag, attrib, **extra)
    ret.text = text
    return ret

def _getURL(env, local, full=False):
    
    url = urlparse.urljoin(env['SCRIPT_NAME'], local)

    if full:
        url = urlparse.urljoin("%s://%s" % (guess_scheme(env), env['HTTP_HOST']), url)

    return url
    
    
