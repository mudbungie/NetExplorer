# This is a graph database using Gremlin and Titan as a backend.

import networkx as nx

class Network(nx.Graph):
    def arpCrawl(self):
        for host in self.nodes():
            arps = host.getArpTable()
            print(arps)

