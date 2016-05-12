# Performs initialization, and returns the database object that we'll be
# interacting with.

from Config import config
from Database import Network
from Router import Router

#from bulbs.neo4jserver import Graph, DEBUG, Config, NEO4J_URI
from bulbs.rexster import Graph, Config

def dbinit():
    yknet = Network()
    router = Router(config['network']['router'])
    yknet.add_node(router)
    yknet.arpCrawl()

    return True

if __name__ == '__main__':
    a = dbinit()
