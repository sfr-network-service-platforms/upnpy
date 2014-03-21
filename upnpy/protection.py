
"""Device protection handling"""

__author__ = 'Antoine Monnet antoine.monnet@sfr.com'
__copyright__ = 'Copyright (c) 2014 SFR (http://www.sfr.com)'
__license__ = 'GNU LESSER GENERAL PUBLIC LICENSE Version 2.1'

import logging

from persist import DB
import ussl
import utils

try:
    from xml.etree import cElementTree as ElementTree
except:
    from xml.etree import ElementTree

DPNS = utils.Namespace('urn:schemas-upnp-org:gw:DeviceProtection', 'dp')
XSINS = utils.Namespace('http://www.w3.org/2001/XMLSchema-instance', 'xsi')
DPLOC = "urn:schemas-upnp-org:gw:DeviceProtection http://www.upnp.org/schemas/gw/DeviceProtection-v1.xsd"

def acl(roles=None, restricted_roles=None):
    def restricted_action(action):        
        action.roles = Roles(roles.split()) if roles is not None else None
        action.restricted_roles = Roles(restricted_roles.split()) if restricted_roles is not None else None
        return action
    return restricted_action

from collections import Set
class Roles(Set):
    def __init__(self, data=None):
        self.data = set(data or [])
    def __contains__(self, key):
        return key in  self.data
    def __iter__(self):
        return self.data.__iter__()
    def __len__(self):
        return len(self.data)
    def __str__(self):
        return " ".join(self.data)
    def __repr__(self):
        return "<Roles %s>" % str(self)

from device import BaseService, StateVariable, action, Action, ActionError, _TextElement

class ACLError(ActionError):
    def __init__(self, code=606, description = None, detail = None):
        super(ACLError, self).__init__(code, description, detail)

class Service(BaseService):

    serviceType = 'urn:schemas-upnp-org:service:DeviceProtection:1'
    serviceId = 'urn:upnp-org:serviceId:DeviceProtection'

    A_ARG_TYPE_ACL = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_IdentityList = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_Identity = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_String = StateVariable('string', sendEvents=False)
    A_ARG_TYPE_Base64 = StateVariable('bin.base64', sendEvents=False)

    SupportedProtocols = StateVariable('string', sendEvents=False)
    SetupReady = StateVariable('boolean')
    
    @action(params=dict(ProtocolType='A_ARG_TYPE_String',
                        InMessage='A_ARG_TYPE_Base64'),
            returns=dict(OutMessage='A_ARG_TYPE_Base64'))
    def SendSetupMessage(self, ProtocolType, InMessage):
        return dict(OutMessage="")

    @action(returns=dict(ProtocolList='SupportedProtocols'))
    def GetSupportedProtocols(self):
        return ''

    @action(returns=dict(RoleList='A_ARG_TYPE_String'))
    def GetAssignedRoles(self, _request):       
        return _request.protection.roles

    @acl(roles='Basic Admin', restricted_roles='Public')
    @action(params=dict(DeviceUDN='A_ARG_TYPE_String',
                        ServiceId='A_ARG_TYPE_String',
                        ActionName='A_ARG_TYPE_String'),
            returns=dict(RoleList='A_ARG_TYPE_String',
                         RestrictedRoleList='A_ARG_TYPE_String'))
    def GetRolesForAction(self, DeviceUDN, ServiceId, ActionName):
        service = self._parent._find(udn=DeviceUDN, id=ServiceId)
        if not service:
            raise ActionError(600, detail="service %s::%s not found" % (DeviceUDN, ServiceId))
        action = getattr(service, ActionName, None)
        if not action or not isinstance(action, Action):
            raise ActionError(600, detail="action %s not found" % ActionName)
        
        if getattr(action, 'roles', None) or getattr(action, 'restricted_roles', None):
            required = action.roles or Roles()
            restricted_roles = action.restricted_roles or Roles()
        else:
            required = Roles(['Public'])
            restricted_roles = Roles()

        return dict(RoleList=required,
                    RestrictedRoleList=restricted_roles)

    @acl(roles='Basic Admin', restricted_roles='Public')
    @action(params=dict(ProtocolType='A_ARG_TYPE_String',
                        Name='A_ARG_TYPE_String'),
            returns=dict(Salt='A_ARG_TYPE_Base64',
                         Challenge='A_ARG_TYPE_Base64'))
    def GetUserLoginChallenge(self, ProtocolType, Name):
        return dict(Salt='', Challenge='')
              
    @acl(roles='Basic Admin', restricted_roles='Public')
    @action(params=dict(ProtocolType='A_ARG_TYPE_String',
                        Challenge='A_ARG_TYPE_Base64',
                        Authenticator='A_ARG_TYPE_Base64'))
    def UserLogin(self, ProtocolType, Challenge, Authenticator):
        return
            
    @action()
    def UserLogout(self):
        return

    @acl(roles='Basic Admin', restricted_roles='Public')
    @action(returns=dict(ACL='A_ARG_TYPE_ACL'))
    def GetACLData(self):

        acl = ElementTree.Element(DPNS('ACL'), {XSINS('schemaLocation'):DPLOC})

        print [str(i) for i in Identity.all()]
        ElementTree.SubElement(acl, DPNS('Identities')).extend(i.desc() for i in Identity.all())

        roles = ElementTree.SubElement(acl, DPNS('Roles'))
        for role in self._collect_roles(self._parent):
            ElementTree.SubElement(roles, DPNS('Role')).append(
                _TextElement(DPNS('Name'), role))

        return utils.tostring(acl, default_namespace=DPNS.ns)

    def _collect_roles(self, device):
        ret = Roles()
        for s in device.services.values():
            for an in dir(s):                
                a = getattr(s, an, None)
                if isinstance(a, Action):
                    ret |= getattr(a, 'roles', None) or Roles()
                    ret |= getattr(a, 'restricted_roles', None) or Roles()
        for d in device.devices.values():
            ret |= self._collect_roles(d)

        return ret

    @acl(roles='Basic Admin', restricted_roles='Public')
    @action(params=dict(IdentityList='A_ARG_TYPE_IdentityList'),
            returns=dict(IdentityListResult='A_ARG_TYPE_IdentityList'))
    def AddIdentityList(self, IdentityList):
        return dict(IdentityListResult='')

    @acl(roles='Admin')
    @action(params=dict(Identity='A_ARG_TYPE_Identity'))
    def RemoveIdentity(self, Identity):
        return

    @acl(roles='Admin', restricted_roles='Basic')
    @action(params=dict(ProtocolType='A_ARG_TYPE_String',
                        Name='A_ARG_TYPE_String',
                        Stored='A_ARG_TYPE_Base64',
                        Salt='A_ARG_TYPE_Base64'))
    def SetUserLoginPassword(self, ProtocolType, Name, Stored, Salt):
        return

    @acl(roles='Admin')
    @action(params=dict(Identity='A_ARG_TYPE_String',
                        RoleList='A_ARG_TYPE_String'))
    def AddRolesForIdentity(self, Identity, RoleList):
        return

    @acl(roles='Admin')
    @action(params=dict(Identity='A_ARG_TYPE_String',
                        RoleList='A_ARG_TYPE_String'))
    def RemoveRolesForIdentity(self, Identity, RoleList):
        return


    def _handle_request(self, request, devser):
                
        rp = request.protection = RequestProtection()

        try:            
            cert = ussl.get_peer_certificate(request.connection.socket)
            #user = None #so.get_context().get_app_data()
        except AttributeError:
            pass
        else:
            if cert:
                cp = ControlPoint.get(
                    ussl.cert_uuid(cert),
                    cert.get_subject().CN)
                self._logger.debug("control point : %s", cp)
                rp.identities.append(cp)

        for i in rp.identities:
            rp.roles |= i.roles

    def _check_acl(self, request, service, action):
       
        rp = request.protection

        if getattr(action, 'roles', None) or getattr(action, 'restricted_roles', None):
            required = action.roles or Roles()
            restricted_roles = action.restricted_roles or Roles()
        else:
            required = Roles(['Public'])
            restricted_roles = Roles()
        
        if rp.roles.isdisjoint(required | restricted_roles):
            raise ACLError(detail="roles '%s' neither in required '%s' nor in restricted '%s'" % (rp.roles, required, restricted_roles))
                           
class RequestProtection(object):
    def __init__(self):
        self.identities = []
        self.roles = Roles(['Public'])


class Identity(object):
    CLASSES = []

    @classmethod
    def all(cls):
        from itertools import chain
        return chain(*[c.all() for c in cls.CLASSES])
        
class User(Identity):    

    @classmethod
    def get(cls, name):
        with DB() as db:
            try:
                return db['user.%s' % name]
            except KeyError:
                u = cls(name)
                db['user.%s' % name] = u
                return u

    def __init__(self, name):
        self.name = name
        self.roles = Roles()

        super(User, self).__init__()

    def desc(self):
        user = ElementTree.Element(DPNS('User'))
        user.extend([
                _TextElement(DPNS('Name'), self.name),
                _TextElement(DPNS('RoleList'), self.roles),
                ])
        return user

    def __str__(self):
        return "<%s %s>" % (self.__class__.__name__, self.name)

    @classmethod
    def all(cls):
        with DB(False) as db:
            return [db[key] for key in db if key.startswith('user.')]

Identity.CLASSES.append(User)

class ControlPoint(Identity):

    @classmethod
    def get(cls, id, name=None):
        with DB() as db:
            try:
                return db['controlpoint.%s' % id]
            except KeyError:
                logging.error('new ControlPoint %s %s', id, name)
                cp = cls(id, name)
                db['controlpoint.%s' % id] = cp
                return cp

    def __init__(self, id, name):
        logging.error('init ControlPoint %s %s', id, name)
        self.id = id
        self.name = name
        self.alias = None
        self.introduced = False
        self.roles = Roles()

        super(ControlPoint, self).__init__()

    def desc(self):
        cp = ElementTree.Element(DPNS('CP'), {DPNS('introduced'):str(int(self.introduced))})
        cp.extend([
                _TextElement(DPNS('Name'), self.name),
                _TextElement(DPNS('ID'), str(self.id)),
                _TextElement(DPNS('RoleList'), self.roles),
                ])
        if self.alias:
            cp.append(_TextElement(DPNS('Alias'), self.alias))
        return cp

    def __str__(self):
        return "<%s %s %s>" % (self.__class__.__name__, self.name, self.id)

    @classmethod
    def all(cls):
        with DB(False) as db:
            return [db[key] for key in db if key.startswith('controlpoint.')]

Identity.CLASSES.append(ControlPoint)
