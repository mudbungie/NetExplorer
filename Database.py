# Networkx-based graph database

import networkx as nx
from NetworkPrimitives import Mac, Ip, Netmask
from Host import Host

class Network(nx.Graph):
    def hosts(self):
        hosts = [host for host in self.nodes if type(host) == Host]
        return hosts
    def ips(self):
        ips = [ip for ip in self.nodes() if type(ip) == Ip]
        return ips
    def macs(self):
        mac = [mac for mac in self.nodes() if type(mac) == Mac]

    # If you need to get everything, just traverse it once.
    def sortNetwork(self):
        ips = []
        macs = []
        hosts = []
        for node in nodes:
            if type(node) == Ip:
                ips.append(node)
            elif type(node) == Mac:
                macs.append(node)
            elif type(node) == Host:
                hosts.append(node)
        return (ips, macs, hosts)

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

    def 

    def arpCrawl(self):
        # Get existing nodes.
        a = self.sortNetwork()
        ips = a[0]
        macs = a[1]
        hosts = a[2]
        for host in hosts:
            # Tries to scan each of the host's interfaces, until it gets a
            # non-empty table.
            try:
                arpTable = host.getArpTable()
                # Making sure it didn't come back empty.
                for arp in arpTable:
                    # Then we add those nodes in.
                    self.add_nodes_from([ip, mac])
                    # Find out if either of them already have an interface.
                    # This is a set for deduplication.
                    interfaces = set(self.findAdj(ip, ntype=Interface) +\
                        self.findAdj(mac, ntype=Interface))
                    if len(interfaces) == 0:
                        # There is no interface, we have to add it.
                        interface = Interface(ip=ip, mac=mac)
                    elif len(interfaces) == 1:
                        # There is an interface already. Add the ip and mac
                        # in case they aren't already there.
                        interface = interfaces[0]
                        interface.ips.add(ip)
                        interface.macs.add(mac)
                    else:
                        # Should never happen.
                        raise RedundantInterfaceError('Redundant link ' +\
                            'on ' + ip + mac)
                    # Regardless, we add connections from the interface
                    # to each of its attributes.
                    self.add_edges_from([(ip, interface), (mac,interface)])
                    # Find out if this interface already belongs to a host.
                    hosts = self.findAdj(interface, ntype=Host)
                    if len(hosts) == 0:
                        # No host, add it.
                        host = Host()
                        self.add_edge(host, interface)
                    elif len(hosts) == 1:
                        # Already there, just make sure that it's connected.
                        self.add_edge(host, interface)
                    else:
                        raise RedundantHostError('Redundant host ' +\
                            'associated with ' + ip + mac)

            except NonResponsiveError:
                # The host is nonresponsive. Flag it.
                pass #FIXME
