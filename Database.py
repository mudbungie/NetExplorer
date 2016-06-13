# I actually want to have a real database backend for write concurrency.
# Easier than writing a thread handler.

import sqlalchemy as sqla
import json
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('sqlite:///netexplorer.sqlite')
meta = MetaData()
Base = declarative_base(metadata=meta)
Session = sqlalchemy.orm.sessionmaker(bind=engine)

class Node(Base):
    # A node from the network. Can be any piece of information.
    __tablename__  = 'nodes'
    nodeid = Column(Integer, primary_key=True)
    value = Column(String(100))
    nodetype = Column(String(25), nullable=False)

    @property
    def attrs(self, *keys):
        if not keys:
            with Session() as s:
                return s.query(Attribute).filter(nodeid == self.nodeid)
        else:
            
    def addattr(self, key, value):
        attr = Atribute(nodeid=self.nodeid, key=key, value=value)
    
    @property
    def edges(self):
        with Session() as s:
            return s.query(Edge).filter(or_(Edge.node1 == self.nodeid, 
                Edge.node2 == self.nodeid))

    @property
    def neighbors(self):
        return [node for edge.nodes in self.edges if node.nodeid != self.nodeid]

    def delete():
        # Deletes connected attributes and edges, then itself.
        for attribute in self.attr:
            attribute.delete()
        for edge in self.edges:
            edge.delete()
        with Session() as s:
            s.delete(self)
            s.commit()
        return True

class Edge(Base):
    # An edge from the network. Connects two nodes.
    __tablename__ = 'edges'
    edgeid = Column(Integer, primary_key=True)
    node1 = Column(ForeignKey('nodes.nodeid'))
    node2 = Column(ForeignKey('nodes.nodeid'))
    nodetype = Column(String(25), nullable=False)
    
    @property
    def nodes(self):
        return set(self.node1, self.node2)

    @property
    def attr(self):
        with Session() as s:
            return s.query(Attribute).filter(edgeid == self.edgeid)
    
    def delete():
        # Delete connected attributes and self.
        for attribute in self.attr:
            attribute.delete()
        with Session() as s:
            s.delete(self)
            s.commit()

class Attribute(Base):
    # Values for nodes.
    __tablename__ = 'attributes'
    attributeid = Column(Integer, primary_key=True)
    # Will only have one or the other of these.
    edgeid = Column(ForeignKey('edges.edgeid'))
    nodeid = Column(ForeignKey('nodes.nodeid'))
    # Actual contents:
    key = Column(String(20))
    value = Column(String(50))

    def delete():
        with Session() as s:
            s.delete(self)
            s.commit()

