#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Host, RemoteController
from mininet.log import CLI
from mininet.util import quietRun

class SDNTopo( Topo ):
    
    def __init__( self ):

        Topo.__init__(self)

        host1 = self.addHost('host1')
        host2 = self.addHost('host2')
        host3 = self.addHost('host3')
        switch = self.addHost('switch')

        for h in host1, host2, host3
            self.addLink(switch, h)

class SDNController( RemoteController ):

    def __init__( self):

        RemoteController.__init__(self, )

topo = SDNTopo()
net = Mininet(topo=topo, controller=RemoteController)
net.start()
CLI(net)
net.stop()
