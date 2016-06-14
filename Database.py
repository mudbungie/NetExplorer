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
    attributes = relationship('Attribute')

    # With no arguments, gives all attributes. With arguments, returns 
    # any attributes that have matching keys.
    @property
    def attrs(self, *keys):
        if not keys:
            with Session() as s:
                return s.query(Attribute).filter(nodeid == self.nodeid).all()
        else:
            attributes = []
            for key in keys:
                results = s.query(Attribute).\
                    filter(and_(nodeid==self.nodeid, key==key)).all()
                # Don't append None.
                if results:
                    attributes += results
            return attributes

    # Insert an attribute with key and value.    
    def addattr(self, key, value):
        attr = Atribute(nodeid=self.nodeid, key=key, value=value)
        with Session() as s:
            s.add(attr)
            s.commit()
    # Delete attributes by key. 
    def delattr(self, key)
        with Session() as s:
            s.query(Attribute).filter(and_(nodeid==self.nodeid, key==key)).\
                delete()
            s.commit()

    @property(self):
        return self.attrs('nodetype')[0]
    
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

class Edge(Base):
    # An edge from the network. Connects two nodes.
    __tablename__ = 'edges'
    edgeid = Column(Integer, primary_key=True)
    node1 = Column(ForeignKey('nodes.nodeid'))
    node2 = Column(ForeignKey('nodes.nodeid'))
    attributes = relationship('Attribute')
    # With no arguments, gives all attributes. With arguments, returns 
    # any attributes that have matching keys.
    @property
    def attrs(self, *keys):
        if not keys:
            with Session() as s:
                return s.query(Attribute).filter(edgeid == self.edgeid).all()
        else:
            attributes = []
            for key in keys:
                results = s.query(Attribute).\
                    filter(and_(edgeid==self.edgeid, key==key)).all()
                # Don't append None.
                if results:
                    attributes += results
            return attributes

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

