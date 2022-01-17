from re import L
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSBridge
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from sys import argv
from time import *
# It would be nice if we didn't have to do this:
# pylint: disable=arguments-differ


class SingleSwitchTopo(Topo):
    def build(self,n=2):
        s0 = self.addSwitch('s0', stp=True)
        for h in range(n):
            host = self.addHost('h%s' % (h+1))
            self.addLink(host, s0)

def Test(num):
    "Create network and run simple performance test"
    topo = SingleSwitchTopo(num+1)
    net = Mininet(topo=topo, host=CPULimitedHost,
                  link=TCLink, autoStaticArp=False)
    net.start()
    info("Dumping host connections\n")
    dumpNodeConnections(net.hosts)
    h1 = net.getNodeByName('h1')
    h1.cmd("sudo python3 ./server_p2p.py %d &" % (num))
    begin_time = time()
    h1 = net.getNodeByName('h2')
    h1.cmd("sudo python3 ./client_CS.py data2")
    for i in range(2, num+2):
        h = net.getNodeByName('h%d' % (i))
        h.cmd("sudo python3 ./client_CS.py data%d"%(i))
    stop_time = time()-begin_time
    print("C/S运行时间为： ", stop_time)
    CLI(net)
    net.stop()


if __name__ == '__main__':    # setLogLevel( 'debug' )
    # Prevent test_simpleperf from failing due to packet loss
    setLogLevel('info')
    number=input("请输入一个整数\n")
    number=int(number)
    Test(number)
