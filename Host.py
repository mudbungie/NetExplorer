# Class for a network object. 

from NetworkPrimitives import Ip, Mac, Interface
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
            return None
    @hostname.setter
    def hostname(self, hostname):
        self.network.node[self]['hostname'] = hostname

    @property
    def updated(self):
        return self.network.node[self]['updated']

    @property
    def vendor(self):
        try:
            return self.network.node[self]['vendor']
        except KeyError:
            return None
    @vendor.setter
    def vendor(self, vendor):
        self.network.node[self]['vendor'] = vendor

    def touch(self):
        # Update timestamp on host.
        self.network.node[self]['updated'] = Toolbox.timestamp()

    def snmpInit(self, community, ip):
        session = easysnmp.Session(hostname=ip, community=community, version=1, timeout=0.5)
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

    def getStatusPage(self, path):
        # Negotiates HTTP auth and JSON decoding for getting data from 
        # the web interface. 
        with requests.Session() as websess:
            for ip in self.ips:
                payload = { 'username':config['network']['radios']['unames'],
                            'password':config['network']['radios']['pwords']}
                loginurl = 'https://' + ip + '/login.cgi?url=/' + path
                statusurl = 'https://' + ip + '/' + path
                # Open the session, to get a session cookie.
                websess.get(loginurl, verify=False, timeout=2)
                # Authenticate, which makes that cookie valid.
                p = websess.post(loginurl, data=payload, verify=False, 
                    timeout=2)
                # Get ze data.
                g = websess.get(statusurl, verify=False, timeout=2)
                # It all comes back as JSON, so parse it.
                try:
                    return = json.loads(g.text)
                except ValueError:
                    # When the json comes back blank.
                    print('Blank JSON at:' self.ip)
                    return False

    def getInterfacePage(self):
        # Get the list of network interfaces from the web interface.
        data = self.getStatusPage('iflist.cgi?_=' + Toolbox.timestamp())
        interfaces = []
        for ifdata in data['interfaces']:
            interface = {}
            interface['mac'] = Mac(ifdata['hwaddr'])
            interface['ip'] = Ip(ifdata['ipv4']['addr'])
            interface['label'] = ifdata['ifname']
            interfaces.append(interface)
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
                bridge{'interfaces'} = set(datum['port'])
                bridge{'macs'} = set(datum['hwaddr'])
                bridges.append(bridge)
            bridge = {}
            bridges[datum['bridge']] = {}
            datum = data.pop()
        return bridges

    def scanHostname(self):
        mib = '1.3.6.1.2.1.1.5'
        responses = self.snmpwalk(mib)
        self.network.node[self]['hostname'] = responses.pop().value
        
    def scanArpTable(self):
        mib = 'ipNetToMediaPhysAddress'
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
                localMacs = ['2', '6', 'a', 'e']
                if mac[1] not in localMacs:
                    # See if we already have this data somewhere.
                    interfaces = set(
                        self.network.findAdj(ip, ntype=Interface) +\
                        self.network.findAdj(mac, ntype=Interface))
                    interface = self.network.getUnique(interfaces, 
                        ntype=Interface, check=mac)
                    # Now, connect the interface to everything.
                    self.network.add_edge(mac, interface)
                    self.network.add_edge(ip, interface)
                    host = self.network.getUnique(interface, ntype=Host)
                    self.network.add_edge(host, interface)
                    # And connect the hosts together
                    if host != self:
                        self.network.add_edge(host, self)
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
                if mac.vendor:
                    self.vendor = mac.vendor
                keyedmacs[index] = mac
            except InputError:
                if len(macr.value) > 0:
                    print('invalid mac:', macr.value)
        if self.vendor == 'ubiquity':
            # Ubiquity devices don't reply to IF-MIB requests for ip addresses,
            # but they have good interfaces. 
            interfaces = self.getInterfacePage
        else:
            # Other hosts are mostly compliant to the IF-MIB.
            ipmib = '1.3.6.1.2.1.4.20.1.2'
            iprs = self.snmpwalk(ipmib)

            keyedips = {}
            for ipr in iprs:
                try:
                    # Ips are many-to-one to interfaces, so gotta be a list.
                    ip = Ip(ipr.oid_index)
                    keyedips[ipr.value].append(mac)
                except KeyError:
                    # Some interfaces will have an IP, but no MAC. 
                    # Not sure why.
                    keyedips[ipr.value] = [ip]
                except InputError:
                    if len(ipr.oid_index) > 0:
                        print('invalid ip:', ipr.oid_index)

            # Mac addresses are unique to interfaces, so build the relationship.
            interfaces = {}
            for key, mac in keyedmacs:
                try:
                    interfaces{mac}.add(ips[key])
                except KeyError:
                    interfaces{mac} = set(ips[key])

           # Now, we are going to assume that we have just obtained an
           # authoritative list of all interfaces for this host, so we're 
           # going to clear out everything elsee, since it might be old data

            for mac, ips in interfaces:
                
            for key in keys:
                try:
                    macs = keyedmacs[key]
                except KeyError:
                    # Means that the address is unmatched. Happens when the MAC is
                    # in the locally managed range.
                    #print(ips[key])
                    macs = []
                try:
                    ips = keyedips[key]
                except KeyError:
                    # There is a MAC without an IP address attached. This is fine.
                    ips = []
                # See if there is an interface already.
                try:
                    interface = [i for i in self.interfaces if self.network.\
                        node[i]['index'] == key][0]
                except KeyError:
                    # There is no existing interface, make one.
                    interface = Interface(self.network)
                    self.network.add_edge(interface, self)
                # Get rid of any inaccurate data associated with the interface.
                for mac in interface.macs:
                    if mac not in macs:
                        self.network.remove_node(mac)
                for interface in interface.ips:
                    if ip not in ips:
                        self.network.remove_node(ip)
                
                # Add in the new data.
                for mac in macs:
                    # Ignore internal local MAC addresses.
                    if not mac[1] in ['2', '6', 'a', 'e']:
                        self.network.add_edge(mac, interface)
                for ip in ips:
                    # Ignore loopback addresses.
                    if not ip.startswith('127'):
                        self.network.add_edge(ip, interface)
                # Finally, associate the interface with the host.
                self.network.add_edge(interface, self)
            self.print()
   
    def print(self):
        try:
            print('Host ' + self.hostname + ':')
        except TypeError:
            # Hostname is not set.
            print('Host:')
        #for interface in self.interfaces:
        #    interface.print()
        print('Discovered', len(self.interfaces), 'interfaces.')
