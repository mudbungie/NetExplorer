# Subscripting a string for validation, because (jingle) always validate...
# your input!

from Exceptions import InputError
import re
from binascii import hexlify

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
            raise Exception('Unsopported encoding ' + encoding)

        # Validate!
        macre = re.compile(r'([a-f0-9]{2}[:]?){6}')
        if not macre.match(macstr):
            raise InputError('Not a MAC address:', macstr)

        return super(Mac, cls).__new__(cls, macstr)


class Ip(str):
    def __new__(cls, address, encoding=None):
        # Figure out what we're being passed, convert anything to strings.
        if not encoding:
            # For just strings
            pass
        elif encoding == 'snmp':
            # Returns from SNMP come with a leading immaterial number.
            address = '.'.join(address.split('.')[1:])
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
                raise InputError('Improper string submitted for IP address')
        except ValueError:
            raise InputError('Not an IP address:' + str(address))
        # Sound like everything's fine!
        return octets

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
                    print(octet, prevOctet, a, bits)
                    raise ValueError('Valid IP address, but not netmask.')
                prevOctet = octet
                octet = 255 - octet
                while octet > 0:
                    bits -= 1
                    # Bitwise left-shift of the octet
                    octet = octet >> 1

            return super(Netmask, cls).__new__(cls, bits)

