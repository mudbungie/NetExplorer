# Network abstraction for handling nodes and edges stored in the database.

from NetworkPrimitives import Mac, Ip, Netmask
from Host import Host, Interface
from Exceptions import *
import Toolbox
from Toolbox import diagprint
import os

import Database

test = True

class Network:
    # Returns objects as defined by the nodes, or just the record itself.
    def _nodecategory(self, nodetype, cls=None):
        s = Database.Session()
        records = s.query(Database.Node).filter_by(nodetype=nodetype).all()
        s.close()
        if cls:
            objs = []
            for record in records:
                objs.append(cls(record.value))
            return records
        else:
            return records

    # The following are the all the typed objects that use _nodecategory.
    def hosts(self): 
        return self._nodecategory('host', cls=Host)
    def ips(self):
        return self._nodecategory('ip', cls=Ip)
    def macs(self):
        return self._nodecategory('mac', cls=Mac)
    # The following are raw record access for the associated records.
    def hostrs(self):
        return self._nodecategory('host')
    def iprs(self):
        return self._nodecategory('ip')
    def macrs(self):
        return self._nodecategory('mac')

    # List of IP addresses that don't have hosts. 
    def orphanedIps():
        return [ipr.value for ipr in self.iprs() if not 
            ipr.typedneighbors('host')]
    # Scan IP addresses that lack hosts. Good for bootstrapping.
    def scanOrphans():
        for orphan in self.orphanedIps():
            results = orphan.scan()
            # False if scan fails.
            if results:
                # If true, results is a dictionary of lists. 
                # We'll compare, but first, cache to reduce DB load.
                knownmacs = self.macrs()
                knownips = self.ips()
                host = False
                # Add new data...
                for mac in results['macs']:
                    if mac not in knownmacs:
                        self.addmac(mac)
                        knownmacs.append(mac)
                        diagprint(test, 'Discovered new mac %s', mac)
                    else:   
                        if
                for ip in results['ips']:
                    if ip not in ips:
                        self.addip(ip)      
                        knownips.append(ip)
                        diagprint(test, 'Discovered new %s', ip)

    # The following functions validate input, add nodes to the network, and
    # make an edge with the host.
    def connect_datapoint(self, session, record):
        session.add(Database.Edge(node1=self._record, node2=record))
    # Takes a string, validates, adds it to network, makes an edge with host.
    def add_ip(self, ip):
        # Validate
        ip = str(Ip(ip))
        # Add to network
        s = Database.Session()
        ip = Database.Node(value=ip, nodetype='ip')
        s.add(ip)
        self.connect_datapoint(s, ip)
        s.commit()
        s.close()
    # Takes a string, validates, adds it to network, makes an edge with host.
    def add_mac(self, mac):
        # Validate
        mac str(Mac(mac))
        s = Database.Session()
        mac = Database.Node(value=mac, nodetype='mac')
        s.add(mac)
        self.connect_datapoint(s, mac)
        s.commit()
        s.close()

class Ip(str):
    def __new__(cls, address, encoding=None):
        # Figure out what we're being passed, convert anything to strings.
        if not encoding:
            # For just strings
            pass
        elif encoding == 'snmp':
            # Returns from SNMP come with a leading immaterial number.
            print('Pre-encoded:', address)
            address = '.'.join(address.split('.')[-4:])
            print('Post-encoded:', address)
        else:
            # Means invalid encoding passed.
            raise Exception('Improper encoding passed with IP address')
        # Now validate!
        cls.octets(address)
        return super(Ip, cls).__new__(cls, address)

    def octets(address):
        try:
            # Split the address into its four octets
            octets = address.split('.')
            octets = [int(b) for b in octets]
            # Throw out anything that isn't a correct octet.
            ipBytes = [b for b in octets if 0 <= b < 256]
            ipStr = '.'.join([str(b) for b in ipBytes])
            # Make sure that it has four octets, and that we haven't lost anything.
            if len(ipBytes) != 4 or ipStr != address:
                raise InputError('Improper string', address, ' submitted for IP address')
        except ValueError:
            raise InputError('Not an IP address:' + str(address))
        # Sound like everything's fine!
        return octets

    @property
    def local(self):
        if self.startswith('127.'):
            return True
        return False

    # Enough validation... on to things you can do with it.
    def scan(self):
        # Start by pinging it. Pings are good.
        # Pings require suid, so we have to use subprocess to invoke the bin.
        pingable = 1
        while not pingable == 0:
            # Goes three times on failures, stops if return 0.
            a = subprocess.call(['ping', '-q', '-c', '1'. '-w', '1', self])
            pingable = (pingable + a) * a
            if pingable > 3:
                return False
        
        
            

class Mac(str):
    def __new__(cls, mac, encoding=None):
        # Usually, I'll be passing a string, but not always, so encodings.
        if not encoding:
            macstr = mac.lower().replace('-',':')
        elif encoding == 'utf-16':
            # The raw data is in hex. Whole nightmare.
            s = str(hexlify(mac.encode('utf-16')))
            macstr = ':'.join([s[6:8], s[10:12], s[14:16], s[18:20], s[22:24],
                s[26:28]]).lower()
            #print(macstr)
        else:
            # Should never happen, means that an unsopported encoding was
            # specified.
            raise Exception('Unsupported encoding ' + encoding)

        # Validate!
        macre = re.compile(r'([a-f0-9]{2}[:]?){6}')
        if not macre.match(macstr):
            raise InputError('Not a MAC address:', macstr)

        return super(Mac, cls).__new__(cls, macstr)

    @property
    def local(self):
        # Tests if the penultimate bit in the first octet is a one.
        # Because seriously, why the fuck is that how we determine this?
        if bin(int(self.__str__().split(':')[0], 16))[-2:-1] == '1':
            return True
        return False
    
    @property
    def vendor(self):
        macvendors = {  'f0:9f:c2':'ubiquiti',
                        'dc:9f:db':'ubiquiti',
                        '80:2a:a8':'ubiquiti',
                        '68:72:51':'ubiquiti',
                        '44:d9:e7':'ubiquiti',
                        '24:a4:3c':'ubiquiti',
                        '04:18:d6':'ubiquiti',
                        '00:27:22':'ubiquiti',
                        '00:15:6d':'ubiquiti',
                        }
        try:
            return macvendors[self[0:8]] 
        except KeyError:
            return None
        
class network(nx.graph):
    def configure(self, config):
        # community strings for snmp
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
    
