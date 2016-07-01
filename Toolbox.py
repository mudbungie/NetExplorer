# Loose functions for doing things
import time
import ipaddress
from datetime import datetime

def timestamp():
    # Returns the current time in epoch format.
    return time.mktime(datetime.now().timetuple())

def getUnique(iterable):
    if len(iterable) > 1:
        raise NonUniqueError('Expected unique', iterable)
    else:
        try:
            return iterable[0]
        except IndexError:
            return None

def ipInNetworks(ip, networks):
    ip = ipaddress.ip_address(ip)
    for network in networks:
        if ip in ipaddress.ip_network(network):
            return True
    return False

class NonUniqueError(Exception):
    pass

# Takes boolean that you have set globally, prints if true.
def diagprint(diagnostic, string):
    if diagnostic:
        print(string)

# String subclassing for validation and profit.
class Mac(str):
    def __new__(cls, mac, encoding=None):
        # Usually, I'll be passing a string, but not always, so encodings.
        if not encoding:
            macstr = mac.lower().replace('-',':')
        elif encoding == 'utf-16':
            # The raw data is in hex. Whole nightmare.
            s = str(hexlify(mac.encode('utf-16')))
            #print(s)
            macstr = ':'.join([s[6:8], s[10:12], s[14:16], s[18:20], s[22:24],
                s[26:28]]).lower()
            #print(macstr)
        else:
            # Should never happen, means that an unsopported encoding was
            # specified.
            raise Exception('Unsupported encoding ' + encoding)

        # Validate!
        macre = re.compile(r'([a-f0-9]{2}[:]?){6}')
        if not macre.match(macstr):
            raise InputError('Not a MAC address:', macstr)

        return super(Mac, cls).__new__(cls, macstr)

    @property
    def local(self):
        # Tests if the penultimate bit in the first octet is a one.
        # Because seriously, why the fuck is that how we determine this?
        if bin(int(self.__str__().split(':')[0], 16))[-2:-1] == '1':
            return True
        return False
    
    @property
    def vendor(self):
        macvendors = {  'f0:9f:c2':'ubiquiti',
                        'dc:9f:db':'ubiquiti',
                        '80:2a:a8':'ubiquiti',
                        '68:72:51':'ubiquiti',
                        '44:d9:e7':'ubiquiti',
                        '24:a4:3c':'ubiquiti',
                        '04:18:d6':'ubiquiti',
                        '00:27:22':'ubiquiti',
                        '00:15:6d':'ubiquiti',
                        }
        try:
            return macvendors[self[0:8]] 
        except KeyError:
            return None
        

class Ip(str):
    def __new__(cls, address, encoding=None):
        # Figure out what we're being passed, convert anything to strings.
        if not encoding:
            # For just strings
            pass
        elif encoding == 'snmp':
            # Returns from SNMP come with a leading immaterial number.
            print('Pre-encoded:', address)
            address = '.'.join(address.split('.')[-4:])
            print('Post-encoded:', address)
        else:
            # Means invalid encoding passed.
            raise Exception('Improper encoding passed with IP address')
        # Now validate!
        cls.octets(address)
        return super(Ip, cls).__new__(cls, address)

    def octets(address):
        try:
            # Split the address into its four octets
            octets = address.split('.')
            octets = [int(b) for b in octets]
            # Throw out anything that isn't a correct octet.
            ipBytes = [b for b in octets if 0 <= b < 256]
            ipStr = '.'.join([str(b) for b in ipBytes])
            # Make sure that it has four octets, and that we haven't lost anything.
            if len(ipBytes) != 4 or ipStr != address:
                raise InputError('Improper string', address, ' submitted for IP address')
        except ValueError:
            raise InputError('Not an IP address:' + str(address))
        # Sound like everything's fine!
        return octets

    @property
    def local(self):
        if self.startswith('127.'):
            return True
        return False

class Netmask(int):
    def __new__(cls, a):
        # Check if it's numeric.
        try:
            a = int(a)
            if 0 <= a <= 32:
                return super(Netmask, cls).__new__(cls, a)
            else:
                raise ValueError('Netmask outside of range')
        # Otherwise, we need to validate the format and do bitwise counting.
        except ValueError:
            # See if it's a valid dotted address.
            a = Ip(a)
            # Then do reverse bitwise counting, since netmask is inverted.
            bits = 32
            prevOctet = 255 # Used for actual value validation.
            for octet in a.octets():
                if octet > prevOctet or (octet != 255 and octet % 2 == 1):
                    #print(octet, prevOctet, a, bits)
                    raise ValueError('Valid IP address, but not netmask.')
                prevOctet = octet
                octet = 255 - octet
                while octet > 0:
                    bits -= 1
                    # Bitwise left-shift of the octet
                    octet = octet >> 1

            return super(Netmask, cls).__new__(cls, bits)

class Interface:
    def __init__(self, network, mac=None, ip=None):
        self.network = network
        self.network.add_node(self)
        if mac:
            self.network.add_edge(self, mac)
        if ip:
            self.network.add_edge(self, ip)

    def print(self):
        print('\tInterface:')
        for mac in self.macs:
            print('\t\tMAC:', mac)
        for ip in self.ips:
            print('\t\tIP:', ip)

    @property
    def ips(self):
        return self.network.findAdj(self, ntype=Ip)
    @property
    def mac(self):
        macs = self.network.findAdj(self, ntype=Mac)
        try:
            return Toolbox.getUnique(macs)
        except IndexError:
            return None
    @mac.setter
    def mac(self, mac):
        self.network.add_edge(self, mac)
    @property
    def host(self):
        hosts = self.network.findAdj(self, ntype=Host)
        return Toolbox.getUnique(hosts)
    @host.setter
    def host(self, host):
        self.network.add_edge(self, host)

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
