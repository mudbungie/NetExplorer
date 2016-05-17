# Networkx-based graph database

import networkx as nx
from NetworkPrimitives import Mac, Ip, Netmask, Interface
from Host import Host
from Exceptions import *

class Network(nx.Graph):
    def configure(self, config):
        self.communities = config['network']['communities']

    def findConnections(self, node, etype=None):
        # This seems like it should be a builtin, but whatever. 
        # I might be mistaking a more idiomatic implementation.
        edges = self.edges(nbunch=node)
        if etype:
            # Filter for edges of the specified variety.
            edges[:] = [e for e in edges if e['etype'] == etype]
        return edges

    def findAdj(self, node, ntype=None):
        # Returns a list of connected nodes that are of the correct type.
        edges = self.findConnections(node)
        if ntype:
            adj = [e[1] for e in edges if type(e[1]) == ntype]
        return adj

    def getUnique(self, nodes, ntype=None, check=None):
        # Returns a single adjacent node, purges violators.
        def makeNew(ntype):
            try:
                obj = ntype()
            except TypeError:
                # Some objects require the database to be passed.
                obj = ntype(self)
            return obj
        if len(nodes) == 0:
            return makeNew(ntype)
        elif len(nodes) == 1:
            return nodes.pop()
            if check:
                # If there was a check, make sure that it's consistent.
                validated = False
                checkobjs = self.findAdj(obj, ntype=type(check))
                if check in checkobjs:
                    validated = True
                if not validated:   
                    self.remove_node(obj)
                return makeNew(ntype)
        else:
            # There shouldn't be more than one connection.
            self.remove_nodes_from(nodes)
            return makeNew(ntype)

    def addHostByIp(self, ip):
        # Validation
        ip = Ip(self, ip)
        interface = Interface(self)
        host = Host(self)
        self.add_node(ip)
        self.add_node(interface)
        self.add_node(host)
        self.add_edge(ip, interface)
        self.add_edge(interface, host)

    def arpCrawl(self):
        # Get existing hosts in the network.
        hosts = [node for node in self.nodes() if type(node) == Host]
        for host in hosts:
            #print(host.ips)
            # Tries to scan each of the host's interfaces, until it gets a
            # non-empty table.
            try:
                host.scanInterfaces()
                host.scanArpTable()

            except NonResponsiveError:
                # The host is nonresponsive. Flag it.
                raise
