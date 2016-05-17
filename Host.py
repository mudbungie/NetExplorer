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
            for ip in ips:
                responses = scan(communities, ip)
                if responses:
                    return responses
                else:
                    # Either the address is dead, or the host is offline.
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
                    print(mac)
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

    def profile(self):
        try:
            status = self.getStatusPage()
            self.online = True
            # This should match what we have in Zabbix.
            self.hostname = status['host']['hostname']
            self.model = status['host']['devmodel']
            self.ap = status['wireless']['essid']
            self.distance = status['wireless']['distance']
            self.rf = {}
            self.rf['signal'] = status['wireless']['signal']
            self.rf['rssi'] = status['wireless']['rssi']
            self.rf['noisef'] = status['wireless']['noisef']
            for entry in status['interfaces']:
                raise
                interface = Interface(Mac(entry['hwaddr']))
                interface.label = entry['ifname']
                interface.speed = entry['status']['speed']

        except requests.exceptions.ConnectionError:
            self.online = False

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
        
    def getArpTable(self):
        # A walk of the ARP table, gives list of dicts

        # MIB for ARP tables
        mib = 'ipNetToMediaPhysAddress'
        responses = self.snmpwalk(mib)
        arpTable = []
        self.arpByMac = {}
        self.arpByIp = {}
        # Conditional, so that we don't error on empty responses
        if responses:
            print('responses did happen')
            ignored = 0
            errors = 0
            for response in responses:
                print(response)
                try:
                    # Validation occurs in the decoding, just move on if they
                    # throw assertion errors.
                    values = {}
                    values['mac'] = Mac(response.value, encoding='utf-16')
                    values['ip'] = Ip(response.oid_index, encoding='snmp')
                    # We also want to know where the ARP record came from.
                    values['source'] = self.ip
                    # We ignore data points that have to do with locally 
                    # administered MAC addresses.
                    localMacs = ['2', '6', 'a', 'e']
                    if values['mac'][1] in localMacs:
                        ignored += 1
                    else:
                        arpTable.append(values)
                        self.arpByMac[mac] = ip
                        self.arpByIp[ip] = mac
                except AssertionError:
                    # Malformed input is to be ignored.
                    errors += 1
                    pass
            print('Recorded', len(arpTable), 'ARP values with', 
                errors, 'errors, ignoring', ignored, 'virtual MAC addresses.')
        else:
            print('Connection failed with host at:', self.ip)
        return arpTable
