# Performs initialization, and returns the database object that we'll be
# interacting with.

from Config import config
from Database import Network
from Router import Router

def dbinit():
    yknet = Network()
    yknet.configure(config)
    yknet.addHostByIp(config['network']['router'])
    yknet.arpCrawl()
    yknet.arpCrawl()

    return yknet

if __name__ == '__main__':
    a = dbinit()
    #print(a.nodes())
