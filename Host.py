# Class for a network object. 

#from NetworkPrimitives import Ip, Mac
#from Config import config
#from Exceptions import *
#import Toolbox
#import easysnmp
import requests
#import json
#import time
#from datetime import datetime
#import uuid
#import geocoder
import sqlalchemy as sqla

import Database
#from Network import Network

# Disable security warnings.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Abstraction layer on top of actual database record.
class Host:
    # Takes the record to start. Everything else is based around that.
    def __init__(self, node_id=False):
        if node_id:  # If we're creating an object from existing data.
            self.node_id = node_id
        else:       # If this is a new host. 
            node = Database.Node(nodetype='Host')
            s = Database.Session()
            s.add(node)
            s.commit()
            self.node_id = node.node_id
            s.close()

    @property
    def _record(self):
        s = Database.Session()
        record = s.query(Node).filter(node.node_id == self.node_id).one()
        s.close()
        return record
    
    @property # Direct access to the records
    def iprs(self):
        return self._record.typedneighbors('ip')
    @property # List of strings
    def ips(self):
        return [ipr.value for ipr in self.iprs]
    @property # Direct access to the records
    def macrs(self):
        return self._record.typedneighbors('mac')
    @property # List of strings
    def macs(self):
        return [macr.value for macr in self.macs]

    @property
    def hostname(self):
        return self._record.value
    @property
    def community(self):
        return self._record.attr('community')
    @community.setter
    def community(self, community):
        self._record.setAttr('community', community)

    def add_ip(ip):
        # We explicitly only take Ip objects that have been introduced to the
        # network.
        if type(ip) != NetworkPrimitives.Ip:
            raise TypeError('Ip objects should have a record.')
        if ip.local:    # Boolean to determine loopback addresses.
            raise TypeError('Loopback address. Don\'t add loopback addresses.')
        if ip not in self.ips:
            s = Database.Session()
            q = s.query(Edge).filter(sqla.and_(node1_id == self.node_id, 
                node1_id == ip.node_id))
            if q.count() != 0: # In case this connection is already known.
                edge = Database.Edge(node1_id = self.node_id,
                    node2_id = ip.node_id)
                s.add(edge)
                s.commit()
            s.close()
        # If it was passed up for some reason, return False
        return False

    '''
    def addAddress(self, address, ifnum=None):
        # Add an IP or MAC address.
        if not address.local:
            if address in self.addresses:
                # Add the ifnum, in case it's not there.
                self.network.node[address]['ifnum'] = ifnum
            else:
                # This is a new mac, or at least not attached to this host.
                self.network.removeSafely(address)
                self.network.add_node(address, ifnum=ifnum)
                self.network.add_edge(self, address, etype='owns')
                # Associate it with any similarly-numbered IPs.
                if ifnum:
                    for a in self.addresses:
                        if 'ifnum' in self.network.node[a] and \
                                self.network.node[a]['ifnum'] == ifnum:
                            self.network.add_edge(address, a, etype='interface')
    @property
    def vendor(self):
        # Take the first recognizable MAC vendor we find.
        for mac in self.macs:
            if mac.vendor:
                return mac.vendor
        return None
    
    @property
    def location(self):
        try:
            return self.network.node[self]['location']
        except KeyError:
            return None
    
    @property
    def coords(self):
        # Geocoords lookup to get address for host.
        return geocoder.google(self.location).latlng
    @property
    def lat(self):
        return self.coords[0]
    @property
    def lng(self):
        return self.coords[1]

    @property
    def arpNeighbors(self):
        return self.network.findAdj(self, ntype=Host, etype='arp')

    @property
    def mgmntip(self):
        # An IP address that is confirmed to work with this host.
        try:
            for ip in self.network.typedNeighbors(self, Ip):
                edge = self.network[self][ip]
                if 'mgmnt' in edge and edge['mgmnt'] == 1:
                    return ip
            # Unless we don't know one.
        except TypeError:
            # Means that there are no IPs.
            pass
        return False
    def setmgmntip(self, ip, isit):
        if isit:
            self.network[self][ip]['mgmnt'] = 1
        else:
            self.network[self][ip]['mgmnt'] = 0


    def snmpInit(self, ip, community):
        print(ip, community)
        session = easysnmp.Session(hostname=ip, community=community, version=1, timeout=1)
        return session

    def snmpwalk(self, mib):
        # Walks specified mib
        ips = self.ips
        # Get a list of communities, starting with any that are known to
        # work on this host.
        communities = self.network.communities.copy()
        if self.community:
            # Means we have a functional community string. Use that first.
            communities.append(self.community)
        communities.reverse()

        def scanAllCommunities(ip):
            for community in communities:
                results = scan(ip, community)
                if results:
                    return results
            return False

        def scan(ip, community):
            session = self.snmpInit(ip, community)
            try:
                responses = session.walk(mib)
                self.community = community
                self.setmgmntip(ip, True)
                print('Response on', ip, 'with', community)
                return responses
            except easysnmp.exceptions.EasySNMPNoSuchNameError:
                # Probably means that you're hitting the wrong kind of device.
                self.community = None
                self.setmgmntip(ip, False)
                raise
            except easysnmp.exceptions.EasySNMPTimeoutError:
                # Either the community string is wrong, or the address is dead.
                print('No response on', ip, 'with', community)
                self.community = None
                self.setmgmntip(ip, False)
                pass
            return False

        # First, we try using known-good settings for communicating with this
        # host.
        if self.mgmntip:
            if self.community:
                results = scan(self.mgmntip, self.community)
                if results:
                    return results
            results = scanAllCommunities(self.mgmntip)
            if results:
                return results
        # If we have no known-good settings, we just iterate over everything.
        for ip in ips:
            if not Toolbox.ipInNetworks(ip, self.network.inaccessiblenets):
                results = scanAllCommunities(ip)
                if results:
                    return results
        return False

    def getStatusPage(self, path, tries=0):
        # Negotiates HTTP auth and JSON decoding for getting data from 
        # the web interface. Functions by requesting IPs until something gives
        # a non-empty response, then authenticates until it gives the correct
        # response. 

        # HTTPS redirect is managed automatically in applicable devices.

        # Mostly got its own function for exception handling.
        def webrequest(verb, session, url, data=None, tries=0):
            if tries < 3:
                try:
                    if verb == 'get':
                        return session.get(url, verify=False, timeout=2)
                    elif verb == 'post':
                        return session.post(url, data=data, verify=False, 
                            timeout=2)
                # Requests has like a billion error codes...
                except (requests.exceptions.ConnectionError, 
                    requests.exceptions.ReadTimeout, 
                    requests.exceptions.ConnectTimeout):
                        tries += 1
                        return webrequest(verb, session, url, data, tries)
            return False

        def iterCreds(url, i=0):
            # Iterate through the list of credentials and return either a 
            # working json dump or False.
            with requests.Session() as websess:
                # Make an initial request to establish session cookies, get 
                # redirected URLS, etc.
                a = webrequest('get', url)
                try:
                    credential = self.network.credentials[i]
                except KeyError:
                    # We've tried all the keys. Fail out.
                    return False
                b = webrequest('post', websess, a.url, data=credential)
                try:
                    return json.loads(b.text)
                except ValueError:
                    # Not valid JSON. Probably not authenticated.
                    # Recurse
                    return itercreds(url, i=i+1)

            # The entirety of the actual function.
            for ip in self.ips:
                statusurl = 'http://' + ip + '/' + path
                status = iterCreds(statusurl)
                if status:
                    return status
            return False

    def getInterfacePage(self):
        # Get the list of network interfaces from the web interface.
        data = self.getStatusPage('iflist.cgi?_=' + str(Toolbox.timestamp()))
        interfaces = {}
        if interfaces:
            for ifdata in data['interfaces']:
                interface = {}
                try:
                    # The typing is for consistency with the SNMP data.
                    interfaces[Mac(ifdata['hwaddr'])] = set([Ip(ifdata['ipv4']['addr'])])
                except KeyError:
                    # Some interfaces won't have an address.
                    pass
        return interfaces

    def getBridgePage(self):
        # Get the bridge page for applicable radios.
        # Data is a big JSON.
        data = self.getStatusPage('brmacs.cgi?brmacs=y&_=' +\
            Toolbox.timestamp())
        brm = data['brmacs']
        bridges = {}
        # The last element is always null.
        datum = data.pop()
        while datum:
            try:
                # Attempt to look it up from the existing bridges.
                bridge = bridges[datum['bridge']]
                bridge['interfaces'].add(datum['port'])
                bridge['macs'].add(datum['hwaddr'])
            except KeyError:
                # If the bridge is unknown, initialize it.
                bridge = {}
                # Sets for deduplication.
                bridge['interfaces'] = set(datum['port'])
                bridge['macs'] = set(datum['hwaddr'])
                bridges.append(bridge)
            bridge = {}
            bridges[datum['bridge']] = {}
            datum = data.pop()
        return bridges

    def getSingleSNMPValue(self, mib, indexInstead=False):
        try:
            responses = self.snmpwalk(mib)
        except NonResponsiveError:
            return None
        try:
            # Take the first response.
            r = responses.pop()
        except AttributeError:
            # Responses empty
            return None
        if indexInstead:
            return r.oid_index
        return r.value

    def scanHostname(self):
        mib = '1.3.6.1.2.1.1.5'
        hostname = self.getSingleSNMPValue(mib)
        # Sanitize
        if hostname:
            hostname = hostname.encode('ascii', 'ignore').decode()
        self.network.node[self]['hostname'] = hostname
        return hostname

    def scanLocation(self):
        mib = '1.3.6.1.2.1.1.6'
        location = self.getSingleSNMPValue(mib)
        if location:
            location = location.encode('ascii', 'ignore').decode()
        self.network.node[self]['location'] = location
        return location
        
    def scanArpTable(self):
        mib = 'ipNetToMediaPhysAddress'
        if self.vendor == 'ubiquiti':
            return False
        else:
            print('No vendor established for:', self.macs)
        responses = self.snmpwalk(mib)
        arps = []
        for response in responses:
            #print(response)
            try:
                # Validation occurs in the decoding, just move on if they
                # throw assertion errors.
                mac = Mac(response.value, encoding='utf-16')
                ip = Ip(response.oid_index, encoding='snmp')
                # We ignore data points that have to do with locally 
                # administered MAC addresses.
                if not mac.local and not ip.local:
                    # See if we already have this data somewhere.
                    self.network.addHostByIp(ip, mac=mac)
                    self.network.add_edge(ip, mac, etype='interface')
            except AssertionError:
                # Malformed input is to be ignored.
                print('malformed input:', response.value, response.oid_index)
        return arps

    def scanInterfaces(self):
        # We scan the mib to mac addresses, which gives us indexing
        # information. We then cross-reference that index against the ips
        macmib = '1.3.6.1.2.1.2.2.1.6'
        macrs = self.snmpwalk(macmib)

        # The MAC address tells us the vendor, which determines some logic.
        for macr in macrs:
            try:
                mac = Mac(macr.value, encoding='utf-16')
                ifnum = macr.oid_index
                self.addAddress(mac, ifnum=ifnum)
            except InputError:
                # Empty interfaces are of no interest.
                if len(macr.value) > 0:
                    # But if they're actually malformed, I want to know.
                    print('invalid mac:', macr.value)

        if self.vendor == 'ubiquiti':
            # Ubiquity devices don't reply to IF-MIB requests for ip addresses,
            # but they will give the data through a web portal.
            interfaces = self.getInterfacePage()
        else:
            # Other hosts are mostly compliant with the IF-MIB.
            ipmib = '1.3.6.1.2.1.4.20.1.2'
            iprs = self.snmpwalk(ipmib)

            for ipr in iprs:
                try:
                    ip = Ip(ipr.oid_index)
                    ifnum = ipr.value
                    self.addAddress(ip, ifnum=ifnum)
                except InputError:
                    print('invalid ip:', ip)

    def to_JSON(self):
        return json.dumps(self.__hash__())
            
    def print(self):
        try:
            print('Host ' + self.hostname + ':')
        except TypeError:
            # Hostname is not set.
            pass

class Interface(str):
    def __init__(self, host):
        self.network = host.network
        self.network.add_edge(self, host)

    def print(self):
        print('\tInterface:')
        for mac in self.macs:
            print('\t\tMAC:', mac)
        for ip in self.ips:
            print('\t\tIP:', ip)
    
    def __hash__(self):
        try:
            return self.__hash
        except AttributeError:
            self.__hash = hash(uuid.uuid4())
            return self.__hash

    def __str__(self):
        print('Interface(', self.mac, self.ips, ')')

    @property
    def ips(self):
        return self.network.findAdj(self, ntype=Ip)
    def add_ip(self, ip):
        self.network.add_edge(self, ip, etype='interface')

    @property
    def mac(self):
        macs = self.network.findAdj(self, ntype=Mac)
        try:
            return Toolbox.getUnique(macs)
        except IndexError:
            return None
        except Toolbox.NonUniqueError:
            # If there are multiples, just give the first one.
            return macs[0]
    @mac.setter
    def mac(self, mac):
        self.network.add_edge(self, mac, etype='interface')
    @property
    def host(self):
        hosts = self.network.findAdj(self, ntype=Host)
        return Toolbox.getUnique(hosts)
    @host.setter
    def host(self, host):
        self.network.add_edge(self, host, etype='interface')

    @property
    def addresses(self):
        # Provides a list of all addresses associated with this device.
        return self.ips + [self.mac]

    @property
    def label(self):
        return self.network.node(self)['label']
    @label.setter
    def label(self, label):
        self.network.node(self)['label'] = label

    @property
    def speed(self):
        return self.network.node(self)['speed']
    @speed.setter
    def speed(self, speed):
        self.network.node(self)['speed'] = speed

class BridgedInterface(Interface):
    # Essentially, makes MAC non-unique for this interface.
    @property
    def macs(self):
        return self.network.findAdj(self, ntype=Mac)
    @property
    def mac():
        raise AttributeError('BridgedInterfaces have macs, not mac.')

    '''
if __name__ == '__main__':
    host0 = Host()
    
