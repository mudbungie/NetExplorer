# Networkx-based graph database

import networkx as nx
from networkx.readwrite import json_graph
import matplotlib.pyplot as plt
import json

from NetworkPrimitives import Mac, Ip, Netmask
from Host import Host, Interface
from Exceptions import *
import Toolbox
import os

class Network(nx.Graph):
    def configure(self, config):
        # Community strings for SNMP
        self.communities = config['network']['communities']
        # Subnets that shouldn't be scanned.
        self.inaccessiblenets = config['network']['inaccessiblenets']
        self.credentials = list(config['network']['credentials'].values())

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

    def removeSafely(self, node):
        try:
            self.remove_node(node)
        except nx.exception.NetworkXError:
            pass

    def findAdj(self, node, ntype=None, etype=None):
        # Returns a list of connected nodes that are of the correct type.
        edges = self.findConnections(node, ntype=ntype, etype=etype)
        if ntype:
            return [e[1] for e in edges if type(e[1]) == ntype]
        else:
            return [e[1] for e in edges]

    def getInterface(self, node):
        try:
            for neighbor in self.neighbors(node):
                if type(neighbor) == Interface:
                    return neighbor
        except nx.exception.NetworkXError:
            return False
                        
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
            try:
                adjacent = [adj for adj in self.neighbors(node)]
            except nx.exception.NetworkXError:
                print(node, type(node))
                raise
            for adj in adjacent:
                if not adj in seen:
                    node = self.findParentHost(adj, seen=seen)
        else:
            return node
        return None

    def typedNeighbors(self, node, ntype):
        try:
            return [n for n in self.neighbors(node) if type(n) == ntype]
        except nx.exception.NetworkXError:
            return []


    def addHostByIp(self, ip, mac=False):
        # Validation
        ip = Ip(ip)
        # If there is already a host, do nothing.
        host = self.typedNeighbors(ip, Host)
        if not host:
            # Otherwise, make one.
            if mac:
                host = Host(self, ip=ip, mac=mac)
            else:
                host = Host(self, ip=ip)
        return host

    @property
    def hosts(self):
        hosts = [h for h in self.nodes() if type(h) == Host]
        return [h for h in self.nodes() if type(h) == Host]

    def arpCrawl(self, timestamp=Toolbox.timestamp()):
        host = self.hosts
        def scan(host):
            # Update the timestamp.
            host.touch()
            # If we can't get a hostname, nothing else is going to work.
            print('Scanning host...', end=' ')
            if host.scanHostname():
                print(host.hostname)
                print('Scanning interfaces...', end=' ')
                host.scanInterfaces()
                host.print()

                print(len(host.addresses), 'interfaces discovered.')
                if not host.vendor == 'ubiquiti':
                    print('Scanning ARP...', end=' ')
                    arps = host.scanArpTable()
                    print(len(arps), 'arp records discovered.')
                #host.print()
                host.scanLocation()
                print('Host located at:', host.location, 'coords:', host.coords)
                print('Host\'s new timestamp:', host.updated)
                print('There are', len(self.nodes()), 'nodes.')
                print('Of which', len([a for a in self.nodes() if type(a) == Host]), 'are hosts.')
                print('Of which', len([a for a in self.nodes() if type(a) == Host\
                    and a.hostname == 'AwbreyM20']), 'are AwbreyM20.')
            else:
                print('Scan failed at', host.ips)
        hosts = self.hosts
        # Sort the list so that the least recently updated is last.
        for host in hosts:
            # Continuously scan the entire network.
            # Take the oldest entry.
            scan(host)
            #nx.draw(self, nx.spring_layout(self), node_size=3, node_color='yellow', font_size=6)
            #plt.tight_layout()
            #plt.savefig('graph.png', format='PNG')

            # Write safely
            nx.write_gml(self, 'network.gml.tmp', stringizer=Toolbox.stringize)
            os.rename('network.gml.tmp', 'network.gml')
            hosts += [h for h in self.hosts if h.updated < timestamp]
    
