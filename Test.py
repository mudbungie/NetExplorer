# Test framework for the NetExplorer package.
import os
import sqlalchemy as sqla
from sqlalchemy.orm import load_only, sessionmaker

import Database
import Ip

def node_creation():
    s = Session()
    n0 = Database.Node(value='cat', nodetype='animal')
    n1 = Database.Node(value='dog', nodetype='animal')
    s.add(n0)
    s.add(n1)
    s.commit()
    q = s.query(Database.Node).options(load_only('value')).all()
    s.close()
    v = [r.value for r in q]
    if 'cat' in v and 'dog' in v:
        print('Node creation: PASS')
        return True
    else:
        print('Node creation: FAIL')
        return False

def edge_creation():
    s = Session()
    q = s.query(Database.Node).all()
    e0 = Database.Edge(node1=q[0], node2=q[1], edgetype='nemesis')
    s.add(e0)
    s.commit()
    q = s.query(Database.Edge).all()
    if len(q) == 1:
        print('Edge creation: PASS')
        return True
    else: 
        print('Edge creation: FAIL')
        return False

def ip_creation():
    s = Session()
    ip = Ip.Ip('1.2.3.4')
    s.add(ip)
    s.commit()
    q = s.query(Ip.Ip).filter_by(nodetype='IPv4').all()
    if q[0].value == '1.2.3.4' and q[0].nodetype == 'IPv4' and q[0].local == False:
        print('IP creation: PASS')
        return True
    else:
        print(q[0].value)
        print('IP creation: FAIL')
        return False

if __name__ == '__main__':
    try:
        os.remove('nxtest.sqlite')
    except FileNotFoundError:
        print('No previous database found. This is fine.')
    #Database.Base.metadata.create_all(Database)
    # Test basic database function, and create test set. 
    sqlitepath = 'sqlite:///nxtest.sqlite'
    engine = sqla.create_engine(sqlitepath)
    Session = sessionmaker(bind=engine)
    Database.Base.metadata.create_all(engine)

    node_creation()
    edge_creation()
    ip_creation()
    #host_creation()
