# Class for a network object. 

from NetworkPrimitives import Ip, Mac
from Interface import Interface
from Config import config
import easysnmp
import requests
import json

# Disable security warnings.
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Host:
    def __init__(self, ip):
        self.hostinit(ip)

    def hostinit(self, ip):
        # A host needs at least an IP address.
        # Which I'll pass two a string subclass for validation.
        self.ip = Ip(ip)
        self.interfaces = [Interface(ip=self.ip)]
        self.community = None
    
    def __str__(self):
        return self.ip

    def snmpInit(self, community):
        session = easysnmp.Session(hostname=self.ip, community=community, version=1, timeout=0.5)
        return session

    def snmpwalk(self, mib):
        # Walks specified mib

        def scan(community):
            session = self.snmpInit(community)
            try:
                responses = session.walk(mib)
                return responses
            except easysnmp.exceptions.EasySNMPNoSuchNameError:
                # Probably means that you're hitting the wrong kind of device.
                return False
            except easysnmp.exceptions.EasySNMPTimeoutError:
                # Either the community string is wrong, or the address is dead.
                return False

        # If we've figured out the community string for this host, use it.
        if self.community:
            responses = scan(community)
            return responses
        # Otherwise, guess until we make it.
        else:
            responses = False
            for community in config['network']['communities']:
                print(community)
                responses = scan(community)
                if responses:
                    # Save that for later, so we don't have to guess.
                    self.community = community
                    return responses
            # The host has rejected all community strings.
            return False

    # Set during init
    @property
    def interfaces(self):
        return self.__interfaces
    @interfaces.setter
    def interfaces(self, interfaces):
        self.__interfaces = interfaces

    # This info is set mostly through zabbix data, though it can be derived
    # from a properly configured host.
    @property
    def hostname(self):
        return self.__hostname
    @hostname.setter
    def hostname(self, hostname):
        self.__hostname = hostname
    @property
    def hostid(self):
        return self.__hostname
    @hostid.setter
    def hostid(self, hostid):
        self.__hostid = hostid

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

    def hasBridge(self):
        # Pull the interface list if it's not already done.
        if len(self.interfaces) == 0:
            #print(self.ip)
            self.getInterfaces()
            #print('finished scan')
        # We'll be comparing different classes of interfaces.
        ath = []
        eth = []
        br = []
        for interface in self.interfaces:
            # Split out the aths and eths.
            if interface.label[0:3] == 'ath':
                ath.append(interface.mac)
            elif interface.label[0:3] == 'eth':
                eth.append(interface.mac)
            elif interface.label[0:2] == 'br':
                br.append(interface.mac)
        # Oddness for efficiency.
        #print('ath',ath)
        #print('eth',eth)
        #print('br',br)
        intersection = [mac for mac in ath if mac in set(eth + br)]
        if len(intersection) > 0:
            # If there are any matches, send the bridged MAC address.
            #print('dupes')
            self.bridge = intersection
            return intersection[0]
        else:
            #print('nodupes')
            self.isBridged = False
            return False

    def getArpTable(self):
        # A walk of the ARP table, gives list of dicts
        print('Scanning ARP table for host at:', self.ip)

        # MIB for ARP tables
        mib = 'ipNetToMediaPhysAddress'
        responses = self.snmpwalk(mib)
        arpTable = []
        self.arpByMac = {}
        self.arpByIp = {}
        # Conditional, so that we don't error on empty responses
        if responses:
            ignored = 0
            errors = 0
            for response in responses:
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
