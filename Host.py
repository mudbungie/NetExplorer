# Class for a network object. 

from NetworkPrimitives import Ip, Mac, Interface
from Config import config
from Exceptions import *
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
        return self.network.node[self]['vendor']
    @vendor.setter
    def hostname(self, vendor)
        self.network.node[self]['vendor'] = vendor

    def touch(self):
        # Update timestamp on host.
        timestamp = time.mktime(datetime.now().timetuple())
        self.network.node[self]['updated'] = timestamp

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

    def getStatusPage(self):
        # Take the 
        with requests.Session() as websess:
            for ip in self.ips:
                try:
                    payload = { 'username':config['network']['radios']['unames'],
                                'password':config['network']['radios']['pwords']}
                    loginurl = 'https://' + ip + '/login.cgi?url=/status.cgi'
                    statusurl = 'https://' + ip + '/status.cgi'
                    # Open the session, to get a session cookie
                    websess.get(loginurl, verify=False, timeout=2)
                    # Authenticate, which makes that cookie valid
                    p = websess.post(loginurl, data=payload, verify=False, 
                        timeout=2)
                    # Get ze data
                    g = websess.get(statusurl, verify=False, timeout=2)
                    # It all comes back as JSON, so parse it.
                    try:
                        status = json.loads(g.text)
                        return status
                    except ValueError:
                        # When the json comes back blank
                        print(self.ip)


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
                    host = self.network.getUnique([interface], ntype=Host)
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
        ipmib = '1.3.6.1.2.1.4.20.1.2'
        try:
            macrs = self.snmpwalk(macmib)
            iprs = self.snmpwalk(ipmib)
        except NonResponsiveError:
            # If SNMP doesn't give us the data, try going for the status page.
            status = self.getStatusPage()
            print(status)

        # Keep a list of known data points, so that we don't purge good data.
        keyedmacs = {}
        for macr in macrs:
            index = macr.oid_index
            #print(index)
            try:
                mac = Mac(macr.value, encoding='utf-16')
                keyedmacs[index].append(mac)
            except KeyError:
                keyedmacs[index] = [mac]
            except InputError:
                if len(macr.value) > 0:
                    print('invalid mac:', macr.value)
        keyedips = {}
        for ipr in iprs:
            try:
                ip = Ip(ipr.oid_index)
                keyedips[ipr.value].append(mac)
            except KeyError:
                keyedips[ipr.value] = [ip]
            except InputError:
                if len(ipr.oid_index) > 0:
                    print('invalid ip:', ipr.oid_index)
        # Combine the keyes from both, so that we don't lose data.
        # Typecasting got gross.
        print(len(keyedips))
        keys = set(list(keyedips.keys()) + list(keyedmacs.keys()))
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
        for interface in self.interfaces:
            interface.print()
