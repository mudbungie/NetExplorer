# Class for a network object. 

from NetworkPrimitives import Ip, Mac
from Config import config
from Exceptions import *
import Toolbox
import easysnmp
import requests
import json
import time
from datetime import datetime
import time
import uuid

# Disable security warnings.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Host(dict):
    def __init__(self, network):
        self.network = network
        # Set the timestamp for unix epoch, unless it was set during init.
        self.network.add_node(self)
        self.network.node[self]['updated'] = 0
        self.community = None
        self.serial = str(uuid.uuid4())

    def __str__(self):
        if self.hostname:
            return self.hostname
        else:
            try:
                return 'Host:' + self.macs[0]
            except IndexError:
                try:
                    return 'Host:' + self.ips[0]
                except IndexError:
                    return str(self.__hash__())

    def __hash__(self):
        try:
            return self.__hash
        except AttributeError:
            self.__hash = hash(uuid.uuid4())
            return self.__hash


    @property
    def interfaces(self):
        return [iface for iface in self.network.neighbors(self)\
            if type(iface) == Interface]

    @property
    def ips(self):
        ips = []
        for interface in self.interfaces:
            ips += self.network.findAdj(interface, ntype=Ip)
        return ips

    @property
    def macs(self):
        macs = []
        for interface in self.interfaces:
            macs += self.network.findAdj(interface, ntype=Mac)
        return macs

    @property
    def community(self):
        return self.network.node[self]['community']
    @community.setter
    def community(self, community):
        self.network.node[self]['community'] = community

    @property
    def addresses(self):
        # Aggregation of all MAC and IP addresses
        return self.macs + self.interfaces

    @property
    def hostname(self):
        try:
            return self.network.node[self]['hostname']
        except KeyError:
            # If we don't know the hostname, try to get it.
            #if self.scanHostname():
            #    return self.network.node[self]['hostname']
            return None
    @hostname.setter
    def hostname(self, hostname):
        self.network.node[self]['hostname'] = hostname

    @property
    def updated(self):
        return self.network.node[self]['updated']
    def touch(self):
        # Update timestamp on host.
        self.network.node[self]['updated'] = Toolbox.timestamp()

    @property
    def vendor(self):
        for interface in self.interfaces:
            try:
                vendor = interface.mac.vendor
                if interface.mac.vendor:
                    return interface.mac.vendor
            except AttributeError:
                # Interface without a MAC
                pass
        return None

    @property
    def arpNeighbors(self):
        return self.network.findAdj(self, ntype=Host, etype='arp')

    def snmpInit(self, community, ip):
        session = easysnmp.Session(hostname=ip, community=community, version=1, timeout=1)
        return session

    def snmpwalk(self, mib):
        # Walks specified mib
        ips = self.ips
        # Get a list of communities, starting with any that are known to
        # work on this host.
        communities = self.network.communities.copy()
        if self.community:
            communities.append(self.community)
        communities.reverse()

        def scan(communities, ip):
            for community in communities:
                session = self.snmpInit(community, ip)
                try:
                    responses = session.walk(mib)
                    self.community = community
                    self.network.node[ip]['scanable'] = True
                    return responses
                except easysnmp.exceptions.EasySNMPNoSuchNameError:
                    # Probably means that you're hitting the wrong kind of device.
                    raise
                except easysnmp.exceptions.EasySNMPTimeoutError:
                    # Either the community string is wrong, or the address is dead.
                    print('No response on', ip, 'with', community)
                    pass
            return False
        
        # Scan IP addresses, starting with any that are known to work.
        for ip in ips:
            try:
                if self.network.node[ip]['scanable'] == True:
                    responses = scan(communities, ip)
                    if responses:
                        # If we've connected, then we're done.
                        return responses
            except KeyError:
                # Scanability has not been ascertained. No special priority.
                pass
        # If there aren't any that are known to work, just try the rest.
        for ip in ips:
            if not Toolbox.ipInNetworks(ip, config['network']['inaccessiblenets']):
                responses = scan(communities, ip)
                if responses:
                    self.network.node[ip]['scanable'] = True
                    return responses
                else:
                    # Either the address is dead, or the host is offline.
                    self.network.node[ip]['scanable'] = False
                    # Either way, the community string isn't to be trusted.
                    self.community = []
        # If we've got nothing at this point, something is wrong.
        raise NonResponsiveError('No response for host at', ips)

    def getStatusPage(self, path, tries=0):
        # Negotiates HTTP auth and JSON decoding for getting data from 
        # the web interface. 
        def urlsByProtocol(protocol, ip, path):
            loginurl = protocol + '://' + ip + '/login.cgi?url=/' + path
            statusurl = protocol + '://' + ip + '/' + path
            return loginurl, statusurl

        with requests.Session() as websess:
            for ip in self.ips:
                payload = { 'username':config['network']['radios']['unames'],
                            'password':config['network']['radios']['pwords']}
                loginurl, statusurl = urlsByProtocol('https', ip, path)
                # In case https is unavailable.
                try:
                    # Open the session, to get a session cookie.
                    websess.get(loginurl, verify=False, timeout=2)
                except requests.exceptions.ConnectionError:
                    loginurl, statusurl = urlsByProtocol('http', ip, path)
                    try:
                        websess.get(loginurl, verify=False, timeout=2)
                        print('HTTPS unavailable for:', ip)
                    except requests.exceptions.ConnectTimeout:
                        # It's inaccessable. 
                        print('No connections available for', ip)
                        return False
                # Authenticate, which makes that cookie valid.
                try:
                    p = websess.post(loginurl, data=payload, verify=False, 
                        timeout=2)
                    # Get ze data.
                    g = websess.get(statusurl, verify=False, timeout=2)
                except requests.exceptions.ConnectionError:
                    tries += 1
                    if tries <= 3:
                        return self.getStatusPage(path, tries)
                    return False
                try:
                    # It all comes back as JSON, so parse it.
                    return json.loads(g.text)
                except ValueError:
                    # When the json comes back blank.
                    print('Blank JSON at:', ip)
                    tries += 1
                    if tries <= 3:
                       return self.getStatusPage(path, tries) 
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

    def scanHostname(self):
        mib = '1.3.6.1.2.1.1.5'
        try:
            responses = self.snmpwalk(mib)
        except NonResponsiveError:
            return False
        self.network.node[self]['hostname'] = responses.pop().value
        return True
        
    def scanArpTable(self):
        mib = 'ipNetToMediaPhysAddress'
        if self.vendor == 'ubiquiti':
            return False
        else:
            print(self.macs, len(self.interfaces))
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
        keyedmacs = {}
        vendor = None
        for macr in macrs:
            index = macr.oid_index
            try:
                mac = Mac(macr.value, encoding='utf-16')
                if not mac.local:
                    keyedmacs[index] = mac
                    if mac.vendor:
                        vendor = mac.vendor
            except InputError:
                if len(macr.value) > 0:
                    print('invalid mac:', macr.value)

        if vendor == 'ubiquiti':
            # Ubiquity devices don't reply to IF-MIB requests for ip addresses,
            # but they will give the data through a web portal.
            interfaces = self.getInterfacePage()
        else:
            # Other hosts are mostly compliant to the IF-MIB.
            ipmib = '1.3.6.1.2.1.4.20.1.2'
            iprs = self.snmpwalk(ipmib)

            keyedips = {}
            for ipr in iprs:
                try:
                    # Ips are many-to-one to interfaces, so gotta be a list.
                    ip = Ip(ipr.oid_index)
                    if not ip.startswith('127.'):
                        keyedips[ipr.value].append(ip)
                except KeyError:
                    # New key, record.
                    keyedips[ipr.value] = [ip]
                except InputError:
                    if len(ipr.oid_index) > 0:
                        print('invalid ip:', ipr.oid_index)

            # Mac addresses are unique to interfaces, so build the relationship.
            interfaces = {}
            for key, mac in keyedmacs.items():
                try:
                    interfaces[mac] |= set(keyedips[key])
                    # Clear this out, because there might be IPs without macs.
                    # ...somehow...
                    del keyedips[key]
                    #print('Interface', mac, '=', interfaces[mac])
                except KeyError:
                    # If this works, then the MAC is new.
                    try:
                        interfaces[mac] = set(keyedips[key])
                    except KeyError:
                        # There are no ips for that MAC.
                        interfaces[mac] = set()
            # Now, go through for any IPs that weren't assigned, and add them.
            for ips in keyedips.values():
                interface = None
                newips = []
                for ip in ips:
                    if ip in self.ips:
                        interface = self.network.getInterface(ip)
                    else:
                        print('IP detected without associated MAC:', ip)
                        newips.append(ip)
                if not interface:
                    interface = Interface(self)
                for ip in newips:
                    interface.add_ip(ip)

        # Now, we are going to assume that we have just obtained an
        # authoritative list of all interfaces for this host, so we're 
        # going to clear out everything else, since it might be old data.
        print('Adding', len(interfaces), 'interfaces...')
        for mac, ips in interfaces.items():
            if not mac in self.macs:
                print('Adding interface:', mac, end=' ')
                # If we don't have this MAC address associated with this host,
                # then we haven't scanned it in its current state. Wipe out 
                # all other data regarding the IPs and MAC address.
                interface = Interface(self)
                self.network.add_edge(interface, self)
                # In case the MAC was somewhere else in the network.
                self.network.purgeConnections(mac)
                self.network.add_edge(interface, mac)
                #print('Added interface:', mac)
            else:
                print('Confirming old interface:', mac, end=' ')
                # The interface is good. Justs double-check the IP addresses.
                interface = self.network.getUnique(mac, ntype=Interface)
                for ip in interface.ips:
                    if not ip in ips:
                        # If an IP didn't show up, that's not right.
                        print('Previously observed interface', ip, 'missing.')
                        self.network.node[ip]['status'] == 'bad'
                        #print('\tPurged IP:', ip)
            for ip in ips:
                # In case this IP was somewhere else in the network.
                self.network.purgeConnections(ip)
                self.network.add_edge(interface, ip)
                print(ip, end=' ')
            print('\nThere are presently', len(self.interfaces), 'interfaces.') 

        return True
            
    def print(self):
        try:
            print('Host ' + self.hostname + ':')
        except TypeError:
            # Hostname is not set.
            print('Host:')
        #for interface in self.interfaces:
        #    interface.print()
        print('Discovered', len(self.interfaces), 'interfaces.')

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
