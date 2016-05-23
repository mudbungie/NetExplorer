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

# Disable security warnings.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Host:
    def __init__(self, network):
        self.network = network
        # Set the timestamp for unix epoch, unless it was set during init.
        self.network.add_node(self)
        self.network.node[self]['updated'] = 0
        self.community = None

    @property
    def interfaces(self):
        return self.network.findAdj(self, ntype=Interface)

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
                    websess.get(loginurl, verify=False, timeout=2)
                    print('HTTPS unavailable for:', ip)
                # Authenticate, which makes that cookie valid.
                p = websess.post(loginurl, data=payload, verify=False, 
                    timeout=2)
                # Get ze data.
                g = websess.get(statusurl, verify=False, timeout=2)
                # It all comes back as JSON, so parse it.
                try:
                    return json.loads(g.text)
                except ValueError:
                    # When the json comes back blank.
                    print('Blank JSON at:', ip)
                    tries += 1
                    if tries <= 3:
                       return self.GetStatusPage(path, tries) 
                    return False

    def getInterfacePage(self):
        # Get the list of network interfaces from the web interface.
        data = self.getStatusPage('iflist.cgi?_=' + str(Toolbox.timestamp()))
        interfaces = {}
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
            # 
            return False
        responses = self.snmpwalk(mib)
        for response in responses:
            #print(response)
            try:
                # Validation occurs in the decoding, just move on if they
                # throw assertion errors.
                mac = Mac(response.value, encoding='utf-16')
                ip = Ip(response.oid_index, encoding='snmp')
                # We ignore data points that have to do with locally 
                # administered MAC addresses.
                if not mac.local:
                    # See if we already have this data somewhere.
                    try:
                        self.network.node[mac]
                        self.network.node[ip]
                        host = self.network.findParentHost(mac)
                        self.network.add_edge(host, self, etype='arp')
                    except KeyError:
                        # This is new data. Add it in to the network.
                        interface = Interface(self.network)
                        host = Host(self.network)
                        self.network.add_edge(host, self, etype='arp')
                        interface.mac = mac
                        interface.host = host
                        interface.add_ip(ip)

            except AssertionError:
                # Malformed input is to be ignored.
                print('malformed input:', response.value, response.oid_index)
        return True

    def scanInterfaces(self):
        # We scan the mib to mac addresses, which gives us indexing
        # information. We then cross-reference that index against the ips
        macmib = '1.3.6.1.2.1.2.2.1.6'
        macrs = self.snmpwalk(macmib)

        # The MAC address tells us the vendor, which determines some logic.
        keyedmacs = {}
        for macr in macrs:
            index = macr.oid_index
            try:
                mac = Mac(macr.value, encoding='utf-16')
                if not mac.vendor == 'local':
                    keyedmacs[index] = mac
            except InputError:
                if len(macr.value) > 0:
                    print('invalid mac:', macr.value)
        #print('Vendor', self.vendor)
        if self.vendor == 'ubiquiti':
            # Ubiquity devices don't reply to IF-MIB requests for ip addresses,
            # but they have good interfaces. 
            interfaces = self.getInterfacePage()
        else:
            for mac in self.macs:
                #print(mac, mac.local)
                pass
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
                except KeyError:
                    # If this works, then the MAC is new.
                    try:
                        interfaces[mac] = set(keyedips[key])
                    except KeyError:
                        # There are no ips for that MAC.
                        interfaces[mac] = set()
    
        # Now, we are going to assume that we have just obtained an
        # authoritative list of all interfaces for this host, so we're 
        # going to clear out everything else, since it might be old data

        for mac, ips in interfaces.items():
            if not mac in self.macs:
                # If we don't have this MAC address associated with this host,
                # then we haven't scanned it in its current state. Wipe out 
                # all other data regarding the IPs and MAC address.
                interface = Interface(self.network)
                self.network.add_edge(interface, self, etype='interface')
                self.network.purgeConnections(mac, etype='interface')
                self.network.add_edge(interface, mac)
                #print('Added interface:', mac)
                for ip in ips:
                    self.network.purgeConnections(ip, etype='interface')
                    self.network.add_edge(interface, ip, etype='interface')
                    #print('\tNew IP:', ip)
                
            else:
                # The interface is good. Justs double-check the IP addresses.
                interface = self.network.getUnique(mac, ntype=Interface)
                #print('Confirmed interface:', mac)
                for ip in interface.ips:
                    if not ip in ips:
                        # If an IP didn't show up, that's not right.
                        self.network.remove_node(ip)
                        #print('\tPurged IP:', ip)
                for ip in ips:
                    if ip not in interface.ips:
                        self.network.add_edge(ip, interface, etype='interface')
                        #print('\tConfirmed IP:', ip)
            
    def print(self):
        try:
            print('Host ' + self.hostname + ':')
        except TypeError:
            # Hostname is not set.
            print('Host:')
        #for interface in self.interfaces:
        #    interface.print()
        print('Discovered', len(self.interfaces), 'interfaces.')

class Interface:
    def __init__(self, network):
        self.network = network
        self.network.add_node(self)

    def print(self):
        print('\tInterface:')
        for mac in self.macs:
            print('\t\tMAC:', mac)
        for ip in self.ips:
            print('\t\tIP:', ip)

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
