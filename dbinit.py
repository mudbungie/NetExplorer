# Performs initialization, and returns the database object that we'll be
# interacting with.

from Config import config
from Database import Network
from Router import Router
from Host import Host
from NetworkPrimitives import *

def dbinit():
    yknet = Network()
    yknet.configure(config)
    host = yknet.addHostByIp(config['network']['router'])
    yknet.arpCrawl()
    return yknet

if __name__ == '__main__':
    a = dbinit()
    #print(a.nodes())
    for node in a.nodes():
        if type(node) == Host:
            node.print()
