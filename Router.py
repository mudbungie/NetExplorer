# Class for a router, which will have ARP data for all attached devices.

# Not mine
from easysnmp import Session
import easysnmp
from binascii import hexlify
from datetime import datetime
import re

# Mine
from NetworkPrimitives import Ip, Mac, Netmask
from Host import Host

class Router(Host):
    def __init__(self, ip):
        # Do the normal things for any network object.
        self.hostinit(ip)

    def getRoutingTable(self):
        print('Scanning routing table for router at:', self.ip)
        # Walk the routing table
        mib = 'ipCidrRouteTable'
        responses = self.walk(mib)
        errors = 0
        routes = {} # Internally, we'll want to do lookups.
        print('Recieved', len(responses), 'SNMP responses from', self.ip)
        for r in responses:
            try:
                # An assumption is that the destinations come first.
                if r.oid == 'ipCidrRouteDest':
                    # Introduce the route.
                    routes[r.oid_index] = {'destination':Ip(r.value),
                                                'router':self.ip}
                # The other conditions just add values.
                elif r.oid == 'ipCidrRouteMask':
                    routes[r.oid_index]['netmask'] = Netmask(r.value)
                elif r.oid == 'ipCidrRouteNextHop':
                    routes[r.oid_index]['nexthop'] = Ip(r.value)
            except KeyError:
                # Would mean that a value came in without our seeing the
                # destination first.
                errors += 1
        # The index on this is useless outside of populating the routes. 
        # I'm going to do a single pass to make a more useful index.
        self.routes = {}
        for r in routes.values():
            self.routes[r['destination']+str(r['netmask'])+r['nexthop']] = r
        print('Parsed', len(self.routes), 'routes.')
        return self.routes

