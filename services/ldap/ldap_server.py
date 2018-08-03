#-*-coding:utf-8-*-
import tempfile, json, os
from twisted.application import service, internet
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.python.components import registerAdapter
from ldaptor.interfaces import IConnectedLDAPEntry
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from ldaptor.ldiftree import LDIFTreeEntry
from ldaptor.protocols import pureldap
from ldap_defaults import LDAP_PORT, DEFAULT_DIT_FILENAME

class TrapLDAPServer(LDAPServer):
    def __init__(self):
        LDAPServer.__init__(self)
        self.AutoAlerts = pureldap.LDAPBERDecoderContext.Identities.values()
        self.AutoAlerts.remove(pureldap.LDAPBindRequest) # This is not automatically an alert
        self.AutoAlerts.remove(pureldap.LDAPSearchRequest) # This is not automatically an alert
        self.AutoAlerts.remove(pureldap.LDAPExtendedRequest) # This is not automatically an alert
    
    def handle(self, msg):
        name = msg.value.__class__

        peer = self.transport.getPeer()
        self.orig_ip = peer.host
        self.orig_port = peer.port

        
        if name in self.AutoAlerts:
            self.raiseAlert(eventname = "LDAP_OperationRequested",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "An LDAP operation (%s) has been attempted" % (name)
                            ) # Active alert

        return LDAPServer.handle(self, msg)

    def handle_LDAPBindRequest(self, request, controls, reply):
        if request.dn == '':
            # anonymous bind (login)
            self.raiseAlert(
                            eventname = "LDAP_AnonymousBind",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "Login attempt to server (no user/pass)",
                            ) # muted alert
        else:
            # named bind (login)
            self.raiseAlert(
                            eventname = "LDAP_BindAttempt",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "Login attempt to server",
                            USERNAME=request.dn,
                            PASSWORD=request.auth
                            ) # real alert

        return LDAPServer.handle_LDAPBindRequest(self, request, controls, reply)

    def handle_LDAPSearchRequest(self, request, controls, reply):
        if (request.baseObject == ''
                and request.scope == pureldap.LDAP_SCOPE_baseObject
                and request.filter == pureldap.LDAPFilter_present('objectClass')):
            self.raiseAlert(
                            eventname = "LDAP_SearchRoot",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "Query attempt for the DSE",
                            ) # muted alert
        else:
            self.raiseAlert(
                            eventname = "LDAP_Search",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "LDAP query: baseObject: %s, scope: %d, filter: %s" % (request.baseObject.encode("latin1"), request.scope, '(' + request.filter.attributeDesc.value + '=' + request.filter.assertionValue.value + ')'),
                            ) # real alert
            pass

        return LDAPServer.handle_LDAPSearchRequest(self, request, controls, reply)

    def handle_LDAPExtendedRequest(self, request, controls, reply):
        if request.requestName == pureldap.LDAPStartTLSRequest.oid:
            self.raiseAlert(
                            eventname = "LDAP_RequestedTLSConnection",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "Client asked to begin TLS communication with server",
                            ) # muted alert
        else:
            self.raiseAlert(
                            eventname = "LDAP_Extended_Operation",
                            originating_ip = self.orig_ip,
                            originating_port = self.orig_port,
                            eventdesc = "Client asked for nonstandard extended operation (%s)" % (request.requestName),
                            ) # real alert
            pass
            
        return LDAPServer.handle_LDAPExtendedRequest(self, request, controls, reply)
    
class Tree(object):

    def __init__(self, dit, username, password):
        dirname = tempfile.mkdtemp('.ldap', 'test-server')
        self.db = LDIFTreeEntry(dirname)
        self.username = username
        self.password = password
        self.dit = dit
        self.init_db()

    def populate_children(self, tree, currnode):
        for item in tree:
            childnode = currnode.addChild(item["name"], item["content"])
            self.populate_children(item["children"], childnode)
    
    def init_db(self):
        """
            Add subtrees to the top entry
            top->country->company->people
        """
        
        try:
            os.chdir(os.path.dirname(os.path.realpath(__file__)))
            fd = open(self.dit, "rb")
        except Exception as e:
            try:
                fd = open(DEFAULT_DIT_FILENAME, "rb")
            except:
                # Supplied AND default DIT files not found.
                # Cannot run a server without a database.
                return

        try:
            tree = json.load(fd)["root"]
        except:
            fd.close()
            fd = open(DEFAULT_DIT_FILENAME, "rb")
            tree = json.load(fd)["root"]

        self.populate_children(tree, self.db)

        # Add the custom username and password
        honeypot_user = ('uid=' + self.username,
                {
                    'objectClass': ['people', 'inetOrgPerson'],
                    'cn': [self.username],
                    'sn': [self.username],
                    'givenName': [self.username],
                    'uid': [self.username],
                    'mail': ['/home/' + self.username + '/mailDir'],
                    'userPassword': [self.password]
                }
            )

        usersnode = self.db.search("(ou=people)")
        usersnode.addCallback(lambda x: x[0].addChild(honeypot_user[0], honeypot_user[1]))

class LDAPServerFactory(ServerFactory):
    """
        Our Factory is meant to persistently store the ldap tree
    """
    protocol = TrapLDAPServer

    def __init__(self, root, alertFunction):
        self.root = root
        self.alertFunction = alertFunction

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        proto.raiseAlert = self.alertFunction
        return proto

class LDAPFunctionalServer:
    def __init__(self, alertFunction, DIT, username = "admin", password = "password"):
        ##### This function is basically a copy paste from the ldaptor site, including the bad comments
        
        # We initialize our tree
        tree = Tree(DIT, username, password)

        # Some unclear thing copy-pasted from the internet example
        registerAdapter(
                        lambda x: x.root,
                        LDAPServerFactory,
                        IConnectedLDAPEntry
                        )
        # Run it
        factory = LDAPServerFactory(tree.db, alertFunction)
        factory.debug = False
        self.factory = factory
        
    def serveForever(self):
        try:
            reactor.listenTCP(LDAP_PORT, self.factory)  # 389 is the default LDAP port
            reactor.run()
        except Exception as e:
            print str(e)
            pass

    def stop(self):
        reactor.stop()

### This part exists for test purposes as we're still using the IPC method during testing and
### it's not possible (or not easy, pretty, and safe) to pass a function through IPC.
##if __name__ == "__main__":
##    import sys
##    from ldap_defaults import ALERT_HEADER, ALERT_TRAILER
##    def alertForTest(eventname, originating_ip, originating_port, eventdesc, **kwargs):
##        print ALERT_HEADER
##        params = {
##            "event_type" : eventname,
##            "originating_ip" : originating_ip,
##            "originating_port" : originating_port,
##            "event_description" : eventdesc
##            }
##
##        for key in kwargs:
##            params[key] = kwargs[key]
##            
##        print json.dumps(params)
##        print ALERT_TRAILER
##        sys.stdout.flush()
##                    
##    f = LDAPFunctionalServer(alertForTest, DEFAULT_DIT_FILENAME)
##    f.serveForever()
