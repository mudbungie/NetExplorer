# I actually want to have a real database backend for write concurrency.
# Easier than writing a thread handler.

# I'm honestly not sure why all of these imports are necessary.
import sqlalchemy as sqla
from sqlalchemy import *
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
import os
from datetime import datetime, timedelta

test = True
if test:
    engine = create_engine('sqlite:///nxtest.sqlite')
else:
    engine = create_engine('sqlite:///netexplorer.sqlite')
meta = MetaData()
Base = declarative_base(metadata=meta)
Session = sessionmaker(bind=engine)

class Node(Base):
    # A node from the network. Can be any piece of information.
    __tablename__  = 'nodes'
    node_id = Column(Integer, primary_key=True)
    value = Column(String(100))
    nodetype = Column(String(20))
    attributes = relationship('Attribute')
    edges = relationship('Edge', primaryjoin='or_(Edge.node1_id==Node.node_id,'
        'Edge.node2_id==Node.node_id)')

    # Return only the attributes that match the provided key.
    def attrs(self, key):
        return [a.value for a in self.attributes if a.key == key]
    # For unique qualities.
    def attr(self, *args):
        # Given one argument, return an attribute that is keyed appropriately.
        # Given two arguments, set the attribute keyed to the first arg to have
        # the value of the second arg. 
        key = args[0]
        if len(args) == 1:
            try:
                return [attr for attr in self.attributes if
                    attr.key == key][0].value
            except IndexError:
                return None
        elif len(args) == 2:
            # If there is an existing attribute, update it, otherwise, insert.
            value = args[1]
            if self.attr(key):
                print('Existing attribute found, updating value.')
                s = Session()
                attr = [a for a in self.attributes if a.key == key][0]
                s.add(attr)
                attr.value = value
                s.commit()
            else:
                print('new')
                self.addAttr(key, value)                
        else:
            raise TypeError('Node.attr() takes 1-2 arguments.')
    
    @property
    def neighbors(self):
        return set([node for edge.nodes in self.edges if \
            node.nodeid != self.nodeid])
    @property
    def typedneighbors(nodetype):
        return [n for n in self.neighbors if n.nodetype == nodetype]

    def addAttr(self, key, value):
        attr = Attribute(key=key, value=value, node_id=self.node_id)
        s = Session()
        s.add(attr)
        s.commit()

    def delete():
        # Deletes connected attributes and edges, then itself.
        for attribute in self.attr:
            attribute.delete()
        for edge in self.edges:
            edge.delete()
        with Session() as s:
            s.delete(self)
            s.commit()

class Edge(Base):
    # An edge from the network. Connects two nodes.
    __tablename__ = 'edges'
    edge_id = Column(Integer, primary_key=True)
    edgetype = Column(String(20))
    node1_id = Column(ForeignKey('nodes.node_id'))
    node2_id = Column(ForeignKey('nodes.node_id'))
    node1 = relationship('Node', foreign_keys=[node1_id])
    node2 = relationship('Node', foreign_keys=[node2_id])
    attributes = relationship('Attribute')
    # With no arguments, gives all attributes. With arguments, returns 
    # any attributes that have matching keys.
    # Return only the attributes that match the provided key.
    @property
    def keyedattrs(self, key):
        return [a.value for a in self.attributes if a.key=='key']

    # If you expect exactly one response.
    @property
    def keyedattr(self, key):
        return keyedattrs(key)[0]
    @property
    def nodes(self):
        return set(self.node1, self.node2)

    def delete():
        # Delete connected attributes and self.
        for attribute in self.attributes:
            attribute.delete()
        with Session() as s:
            s.delete(self)
            s.commit()

class Attribute(Base):
    # Values for nodes.
    __tablename__ = 'attributes'
    attributeid = Column(Integer, primary_key=True)
    # Will only have one or the other of these.
    edge_id = Column(ForeignKey('edges.edge_id'))
    node_id = Column(ForeignKey('nodes.node_id'))
    # Actual contents:
    key = Column(String(20))
    value = Column(String(50))

    def delete():
        with Session() as s:
            s.delete(self)
            s.commit()

if __name__ == '__main__':
    # I guess that this is technically a shitty unit test.
    try:
        os.remove('nxtest.sqlite')
    except FileNotFoundError:
        print('No previous database found. This is fine.')
        pass
    Base.metadata.create_all(engine)
    s = Session()
    n0 = Node(value='cats')
    n1 = Node(value='dogs')
    e = Edge(node1=n0, node2=n1)
    s.add(n0)
    s.add(n1)
    s.commit()
    s.add(e)
    s.commit()
    s.add(n0)
    s.commit()
    s.flush()
    n0.attr('0', '1')
    print(n0.attr('0'))
    n0.attr('0', '2')
    print(n0.attr('0'))
    print(len(n0.attributes))
    print(len(n0.edges))
