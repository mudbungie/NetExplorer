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

def stringize(data):
    # Always returns a string.
    return str(data)

# Exceptions

class NonUniqueError(Exception):
    pass
