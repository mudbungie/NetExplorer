# I actually want to have a real database backend for write concurrency.
# Easier than writing a thread handler.

# I'm honestly not sure why all of these imports have to be explicit.
import sqlalchemy as sqla
from sqlalchemy import * # I seriously can't use sqla.* on some things? Why?
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
import os
from datetime import datetime, timedelta

from Toolbox import diagprint

#FIXME do all list comprehensions with generators, dummy.

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
    _edges = relationship('Edge', primaryjoin='or_(Edge.node1_id==Node.node_id,'
        'Edge.node2_id==Node.node_id)')

    # Return only the attributes that match the provided key.
    # This is implemented only because the entire concept of a session is dumb.
    def attrs(self, *args):
        s = Session()
        if args:
            key = args[0]
            diagprint(test, key)
            q = s.query(Attribute).filter(and_(Attribute.node_id==self.node_id, 
                Attribute.key==key))
        else:
            q = s.query(Attribute).filter_by(node_id=self.node_id)
        return [a for a in q.all()]
    # For unique qualities.
    def attr(self, *args):
        # Given one argument, return an attribute that is keyed appropriately.
        # Given two arguments, set the attribute keyed to the first arg to have
        # the value of the second arg. 
        key = args[0]
        if len(args) == 1:
            try:
                return self.attrs(key)[0].value
            except IndexError:
                return None
        elif len(args) == 2:
            # value = args[1] # For clarity
            self.setAttr(key, args[1])
        else:
            raise TypeError('Node.attr() takes 1-2 arguments.')

    # Internal. Use setAttr.
    def addAttr(self, s, key, value):
        attr = Attribute(key=key, value=value, node_id=self.node_id)
        s.add(attr)
    # Internal. Use setAttr.
    def updateAttr(self, s, key, value):
        attr = self.attrs(key)[0]
        s.add(attr)
        attr.value = value
    def setAttr(self, key, value):
        s = Session()
        s.add(self)
        try:
            self.updateAttr(s, key, value)
        except IndexError:
            self.addAttr(s, key, value)
        s.commit()
        s.close()

    @property
    def neighbors(self):
        return set([node for edge.nodes in self._edges if \
            node.nodeid != self.nodeid])
    @property
    def typedneighbors(nodetype):
        return [n for n in self.neighbors if n.nodetype == nodetype]

    def delete():
        # Deletes connected attributes and edges, then itself.
        for attribute in self.attr:
            attribute.delete()
        for edge in self._edges:
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
    s.close()
    n0.attr('0', '1')
    print('Attribute value 0', n0.attr('0'))
    n0.attr('0', '2')
    print('Attribute value 0', n0.attr('0'))
    print(len(n0.attrs()))
    print(len(n0._edges))
    print([v.value for v in s.query(Attribute).filter_by(node_id = '1').all()])
