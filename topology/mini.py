#!/usr/bin/env python3
"""
Minimal Topology to test the Ryu L2 Learning Switch Controller
1 Switch, 2 Hosts. No loops. Bulletproof Controller setup.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class MiniTopo(Topo):
    def build(self):
        # 1 Dumb Switch
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')

        # 2 Hosts on a flat L2 subnet
        h1 = self.addHost('h1', ip='10.0.0.1/8', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/8', mac='00:00:00:00:00:02')

        # Direct links
        self.addLink(h1, s1)
        self.addLink(h2, s1)

def run_mini():
    topo = MiniTopo()
    
    # THE FIX: build=False forces Mininet to wait for our explicit commands
    net = Mininet(topo=topo, build=False, link=TCLink, switch=OVSSwitch)
    
    info("*** Adding Controller\n")
    # This is now guaranteed to be the ONLY controller
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    info("*** Building Network\n")
    net.build()  # Now we actually wire the simulated hardware together
    
    info("*** Starting Network\n")
    net.start()
    
    info("*** Entering CLI\n")
    CLI(net)
    
    info("*** Stopping Network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_mini()
