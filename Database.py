# Networkx-based graph database

import networkx as nx
from NetworkPrimitives import Mac, Ip, Netmask, Interface
from Host import Host
from Exceptions import *

class Network(nx.Graph):
    def configure(self, config):
        self.communities = config['network']['communities']

    def findConnections(self, node, etype=None, ntype=None):
        # This seems like it should be a builtin, but whatever. 
        # I might be mistaking a more idiomatic implementation.
        edges = self.edges(nbunch=node)
        if etype:
            # Filter for edges of the specified variety.
            edges[:] = [e for e in edges if e['etype'] == etype]
        if ntype:
            # Filter for edges with the specified ends.
            edges[:] = [e for e in edges if type(e[1] == ntype)]
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
        adj = []
        # May or may nor be iterable.
        try:
            for node in nodes:
                adj += self.findAdj(node, ntype=ntype)
        except TypeError:
            # Not iterable, just one node.
            adj += self.findAdj(nodes, ntype=ntype)

        if len(adj) == 0:
            return makeNew(ntype)
        elif len(adj) == 1:
            obj = adj.pop()
            if check:
                # If there was a check, make sure that it's consistent.
                validated = False
                checkobjs = self.findAdj(obj, ntype=type(check))
                if check in checkobjs:
                    validated = True
                if not validated:   
                    print('purged', obj)
                    self.remove_node(obj)
                new = nameNew(ntype)
                for node in nodes:
                    self.add_edge(new, node)
                return new 
            # If there wasn't a check, just return the only value.
            return obj
        else:
            # There shouldn't be more than one connection.
            print('conflict in', nodes, 'prompted purge of', adj)
            self.remove_nodes_from(adj)
            return makeNew(ntype)

    def addHostByIp(self, ip):
        # Validation
        ip = Ip(ip)
        interface = Interface(self)
        host = Host(self) # Adds itself with initialization.
        self.add_node(ip)
        self.add_node(interface)
        self.add_edge(ip, interface)
        self.add_edge(interface, host)
        return host

    def arpCrawl(self, hosts):
        # Let's just get typecasting out of the way.
        hosts = set(hosts)
        # Get existing hosts in the network.
        while len(hosts) > 0:
            # Sort the list so that the least recently updated is last.
            hostlist = sorted(hosts, key=lambda h: self.node[h]['updated'], 
                reverse=True)
            # Take the oldest entry.
            host = hostlist.pop()
            # Tries to scan each of the host's interfaces, until it gets a
            # non-empty table.
            try:
                # Update the timestamp.
                host.touch()
                print('Scanning host: ')
                host.scanHostname()
                print(host.hostname)
                print('Scanning interfaces...')
                host.scanInterfaces()
                print('Scanning ARP...')
                host.scanArpTable()
                host.print()
                # Add newly discovered hosts in a deduplicated fashion.
                hosts.update(self.findAdj(host, ntype=Host))
            except NonResponsiveError:
                # The host is nonresponsive. Flag it.
                print('No response.')

