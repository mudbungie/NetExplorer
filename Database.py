# Networkx-based graph database

import networkx as nx

from NetworkPrimitives import Mac, Ip, Netmask
from Host import Host, Interface
from Exceptions import *
import Toolbox

class Network(nx.Graph):
    def configure(self, config):
        self.communities = config['network']['communities']

    def findConnections(self, node, etype=None, ntype=None):
        # This seems like it should be a builtin, but whatever. 
        # I might be mistaking a more idiomatic implementation.
        try:
            edges = self.edges(nbunch=node, data=True)
        except nx.exception.NetworkXError:
            print(type(node))
            print(node)
            raise
        if etype:
            # Filter for edges of the specified variety.
            tempedges = []
            for edge in edges:
                try:
                    if edge[2]['etype'] == etype:
                        tempedges.append(edge)
                except KeyError:
                    # Means that it doesn't have that descriptor, in which 
                    # case we don't want it.
                    #print(edge)
                    pass
            edges = tempedges
        if ntype:
            # Filter for edges with the specified ends.
            edges[:] = [e for e in edges if type(e[1] == ntype)]
        return edges

    def purgeConnections(self, node, etype=None, ntype=None):
        for edge in self.findConnections(node, etype=etype, ntype=ntype):
            self.remove_edge(edge[0], edge[1])

    def findAdj(self, node, ntype=None, etype=None):
        # Returns a list of connected nodes that are of the correct type.
        edges = self.findConnections(node, ntype=ntype, etype=etype)
        if ntype:
            return [e[1] for e in edges if type(e[1]) == ntype]
        else:
            return [e[1] for e in edges]

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

    def findParentHost(self, node, seen=[]):
        # Take a node, walk until you run into a host.
        if type(node) != Host:
            seen.append(node)
            for adj in self.findAdj(node):
                if not node in seen:
                    node = self.findParentHost(adj, seen=seen)
        return node

    def addHostByIp(self, ip):
        # Validation
        ip = Ip(ip)
        interface = Interface(self)
        host = Host(self) # Adds itself with initialization.
        self.add_node(ip)
        self.add_node(interface)
        self.add_edge(ip, interface, etype='interface')
        self.add_edge(interface, host, etype='interface')
        return host

    @property
    def hosts(self):
        return [h for h in self.nodes() if type(h) == Host]

    def arpCrawl(self, timestamp=Toolbox.timestamp()):
        host = self.hosts
        def scan(host):
            # Update the timestamp.
            host.touch()
            # If we can't get a hostname, nothing else is going to work.
            if host.scanHostname():
                print('Hostname', host.hostname)
                print('Scanning interfaces...')
                host.scanInterfaces()
                print('Scanning ARP...')
                host.scanArpTable()
                #host.print()
                print('Host\'s new timestamp:', host.updated)
                print('There are', len(self.nodes()), 'nodes.')
                print('Of which', len([a for a in self.nodes() if type(a) == Host and a.hostname == 'AwbreyM20']), 'are AwbreyM20.')
            else:
                print('Host nonresponsive at', host.ips)
        hosts = self.hosts
        # Sort the list so that the least recently updated is last.
        for host in hosts:
            # We're going to continually update the hosts list until we've
            # scanned the entire network, in
            #hostsort = sorted(self.hosts, key=lambda h: self.node[h]['updated'], 
            #    reverse=True)
            #hosts = [h for h in hostsort if h.updated < timestamp]
            # Take the oldest entry.
            scan(host)
            hosts += [h for h in self.hosts if h.updated < timestamp]
        
