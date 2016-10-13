# Class for IP addresses.

# Most of this is about subscripting strings for validation, because (jingle)
# always validate... your input!

import Database
import re

def snmpdecode(address):
    print('Pre-encoded: %s' % address)


class Ip(Database.Node):
    def __init__(self):
        # Begin by validating. Trust nothing. 
        ipv4 = address.split('.')
        ipv6 = address.split(':')
        if len(ipv4) == 4:
            for octet in ipv4:
                try: 
                    if 0 < int(octet)< 256:
                        self.nodetype = 'IPv4' # Everything is fine
                        self.value = address
                    else:
                        raise TypeError('.-delimited integers out of range.')
                except ValueError:
                    raise TypeError('.-delimited non-integers in address.')
        elif len(ipv6) == 8:
            raise TypeError('I haven\'t added ipv6 support.')
        else:
            raise TypeError('Not an IP address.')
    
    def octets(self):
        return self.value.split('.')

    @property
    def local(self):
        if int(octets[0]) == 127:
            return True
        else:
            return False
        
'''
class IpString(str):
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
'''

if __name__ == '__main__':
    snmpdecode('works')
