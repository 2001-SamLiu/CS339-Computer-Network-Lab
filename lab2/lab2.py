import sys

from functools import partial

from mininet.net import Mininet
from mininet.node import UserSwitch, OVSKernelSwitch, Controller
from mininet.topo import Topo
from mininet.log import lg, info
from mininet.util import dumpNetConnections, irange, quietRun
from mininet.link import TCLink
from mininet.log import setLogLevel,info
from mininet.cli import CLI
flush = sys.stdout.flush


class LinearTestTopo( Topo ):
    "Topology for a string of N hosts and N-1 switches."

    # pylint: disable=arguments-differ
    def build( self):
        # Create switches and hosts
        h1=self.addHost('h1')
        h2=self.addHost('h2')
        h3=self.addHost('h3')
        s1=self.addSwitch('s1')
        s2=self.addSwitch('s2')
        s3=self.addSwitch('s3')
        self.addLink(h1,s1)
        self.addLink(h2,s2)
        self.addLink(h3,s3)
        # self.addLink(s1,s2,bw=10)
        self.addLink(s1,s2,bw=10,loss=5)
        # self.addLink(s1,s3,bw=10)
        self.addLink(s1,s3,bw=10,loss=5)
        self.addLink(s2,s3)
def run():
    topo=LinearTestTopo()
    net=Mininet(topo=topo,link=TCLink,waitConnected=True)
    net.start()
    dumpNetConnections(net)
    h1,h2,h3=net.getNodeByName('h1','h2','h3')
    # net.iperf((h1,h3),l4Type='TCP')
    # net.iperf((h2,h3),l4Type='TCP')
    # net.iperf((h1,h2),l4Type='TCP')
    # net.ping((h1,h2))
    CLI(net)
    net.stop()
if __name__=='__main__':
    setLogLevel('info')
    run()