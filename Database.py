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
    attributes = Column(String(150)) # JSON dump of attributes.

    @property
    def attr(self):
        return json.loads(self.attributes)
    @attr.setter(self, attr):
        session = Session()
        self.attributes = json.dumps(attr)
        session.add(self)
        session.commit()
    
    @property
    def edges(self):
        with Session() as s:
            return s.query(Edge).filter(or_(Edge.node1 == self.nodeid, 
                Edge.node2 == self.nodeid))

    @property
    def neighbors(self):
        return [node for edge.nodes in self.edges if node.nodeid != self.nodeid]
    
class Edge(Base):
    # An edge from the network. Connects two nodes.
    __tablename__ = 'edges'
    edgeid = Column(Integer, primary_key=True)
    node1 = Column(ForeignKey('nodes.nodeid'))
    node2 = Column(ForeignKey('nodes.nodeid'))
    nodetype = Column(String(25), nullable=False)
    
    nodes = set(node1, node2)

class NodeAttribute(Base):
    # Values for nodes.
    __tablename__ = 'nodeattributes'
    node = Column(ForeignKey('nodes.value'))
    key = Column(String(20))
    value = Column(String(50))

class EdgeAttribute(Base):
    # Values for edges.
    __tablename__ = 'edgeattributes'
    edge = Column(ForeignKey('edges.value'))
    key = Column(String(20))
    value = Column(String(50))


