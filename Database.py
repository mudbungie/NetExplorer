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
                arpTable = host.getArpTable()[0]
                # Making sure it didn't come back empty.
                for arp in arpTable:
                    # Add in all the data that we have.
                    self.add_node(mac)
                    self.add_node(ip)
                    self.add_edge(mac, ip, etype="interface")
                    # Plus, connect that device to the host that we scanned.


                    self.add_edge(mac, , etype="data link")
            except NonResponsive
