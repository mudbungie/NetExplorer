# Class for a network object. 

from NetworkPrimitives import Ip, Mac, Interface
from Config import config
from Exceptions import *
import easysnmp
import requests
import json

# Disable security warnings.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Host:
    def __init__(self, network):
        self.network = network

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

    def snmpInit(self, community, ip):
        session = easysnmp.Session(hostname=ip, community=community, version=1, timeout=0.5)
        return session

    def snmpwalk(self, mib):
        # Walks specified mib
        ips = self.ips

        def scan(communities, ip):
            for community in communities:
                session = self.snmpInit(community, ip)
                try:
                    responses = session.walk(mib)
                    self.community = community
                    return responses
                except easysnmp.exceptions.EasySNMPNoSuchNameError:
                    # Probably means that you're hitting the wrong kind of device.
                    raise
                except easysnmp.exceptions.EasySNMPTimeoutError:
                    # Either the community string is wrong, or the address is dead.
                    pass
            print('scan failed with community',community,'on',ip)
            return False
        
        try:
            # If we've figured out the community string for this host, use it.
            # Typecasting as list, because unknown attempts iterate.
            communities = [self.community]
            # First, try to scan those that are explicitly known to be 
            # accessible.
            for ip in ips:
                if self.network.node[ip]['scanable'] == True:
                    responses = scan(communities, ip)
                    if responses:
                        return responses
            # If there aren't any that are known to work, just try the rest.
            for ip in ips:
                responses = scan(communities, ip)
                if responses:
                    self.network.node(ip)['scanable'] = True
                    return responses
                else:
                    # Either the address is dead, or the host is offline.
                    self.network.node(ip)['scanable'] = False
                    # Either way, the community string isn't to be trusted.
                    self.community = None
                    # And we'll try scanning with the network's list.
        except KeyError:
            pass
        # We haven't figured that out, use the Network's list.
        communities = self.network.communities
        # We didn't make it with the previous community. 
        for ip in ips:
            responses = scan(communities, ip)
            if responses:
                return responses
        # If we've got nothing at this point, something is wrong.
        raise NonResponsiveError('No response for host at', ips)

    def getStatusPage(self):
        # Take the 
        with requests.Session() as websess:
            payload = { 'username':config['radios']['unames'],
                        'password':config['radios']['pwords']}
            loginurl = 'https://' + self.ip + '/login.cgi?url=/status.cgi'
            statusurl = 'https://' + self.ip + '/status.cgi'
            # Open the session, to get a session cookie
            websess.get(loginurl, verify=False, timeout=2)
            # Authenticate, which makes that cookie valid
            p = websess.post(loginurl, data=payload, verify=False, timeout=2)
            # Get ze data
            g = websess.get(statusurl, verify=False, timeout=2)
            # It all comes back as JSON, so parse it.
            try:
                self.status = json.loads(g.text)
            except ValueError:
                # When the json comes back blank
                print(self.ip)
        return self.status

    def hasMac(self, mac):
        # Simple. Just find out if this host has a given hwaddr.
        matchingInterfaces = []
        for interface in self.interfaces.values():
            if interface.mac == mac:
                matchingInterfaces.append(interface.label)
        if len(matchingInterfaces) > 0:
            #print('Matching interface found on', ', '.join(matchingInterfaces))
            return True
        #print('No match')
        return False
        
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
                    host = self.network.getUnique([interface], ntype=Host)
                    self.network.add_edge(host, interface)
                    interface = Interface()
            except AssertionError:
                # Malformed input is to be ignored.
                print('malformed input:', response.value, response.oid_index)
        else:
            print('Connection failed with host at:', self.ip)
        return arpTable

    def scanInterfaces(self):
        # We scan the mib to mac addresses, which gives us indexing
        # information. We then cross-reference that index against the ips
        macmib = '1.3.6.1.2.1.2.2.1.6'
        ipmib = '1.3.6.1.2.1.4.20.1.2'
        macrs = self.snmpwalk(macmib)
        macs = {}
        for macr in macrs:
            index = macr.oid_index
            #print(index)
            try:
                mac = Mac(macr.value, encoding='utf-16')
                macs[index] = mac
            except InputError:
                if len(macr.value) > 0:
                    print('invalid mac:', macr.value)
        iprs = self.snmpwalk(ipmib)
        ips = {}
        for ipr in iprs:
            try:
                ips[ipr.value] = Ip(ipr.oid_index)
            except InputError:
                if len(ipr.oid_index) > 0:
                    print('invalid ip:', ipr.oid_index)
        # Combine the keyes from both, so that we don't lose data.
        # Typecasting got gross.
        keys = set(list(ips.keys()) + list(macs.keys()))
        for key in keys:
            try:
                mac = macs[key]
            except KeyError:
                
                print(ips[key])
            interface = Interface(self.network)
            try:
                ip = ips[key]
                self.network.add_edge(ip, interface)
            except KeyError:
                # There is a MAC without an IP address attached. This is fine.
                pass
            # Ignore internal local MAC addresses
            localMacs = ['2', '6', 'a', 'e']
            if mac[1] not in localMacs:
                self.network.add_edge(mac, interface)
                self.network.add_edge(interface, self)
        
    def getInterfaces(self):
        # Use SNMP to retrieve info about the interfaces.
        #mib = 'iso.org.dod.internet.mgmt.mib_2.interfaces.ifTable.ifEntry.ifPhysAddress'
        macmib = 'ifPhysAddress'
        snmpmacs = self.snmpwalk(macmib)
        descmib = 'ifDescr'
        ifnames = self.snmpwalk(descmib)
        if snmpmacs:
            self.online = True
            #print('ON:', self.ip)
            for snmpmac in snmpmacs:
                # Filter out empty responses.
                if len(snmpmac.value) > 0:
                    mac = Mac(snmpmac.value, encoding='utf-16')
                    #print(mac)
                    interface = (Interface(mac))
                    for ifname in ifnames:
                        # Get the associated name of the interface.
                        if ifname.oid_index == snmpmac.oid_index:
                            label = ifname.value
                    interface.label = label
                    #print(interface, interface.label)
                    self.interfaces[mac] = interface
            return self.interfaces
        else:
            self.online = False
            #print('OFF:', self.ip)
            return None
    
