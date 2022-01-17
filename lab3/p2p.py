import os
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
Host = '10.0.0.1'
Port = 2021


class SingleSwitchTopo(Topo):
    def build(self, n=2):
        s0 = self.addSwitch('s0', stp=True)
        for h in range(n):
            host = self.addHost('h%s' % (h+1))
            self.addLink(host, s0)


def create_topo(num):
    topo = SingleSwitchTopo(num+1)
    net = Mininet(topo=topo, host=CPULimitedHost,
                  link=TCLink, autoStaticArp=False)
    net.start()
    h1 = net.getNodeByName('h1')
    h1.cmd("sudo python3 ./server_p2p.py %d &" % (num))
    begin_time=time()
    for i in range(2, num+2):
        h = net.getNodeByName('h%d' % (i))
        name = ('h%d' % (i))
        if i != (num+1):
            h.cmd("sudo python3 ./client_p2p.py %s %d %d &" % (name,i,num))
        if i==(num+1):
            h.cmd("sudo python3 ./client_p2p.py %s %d %d " % (name,i,num))
    run_time=time()-begin_time
    # for i in range(2,num+2):
    #     client_name=('h%d'%(i))
    #     os.remove(client_name+"_tmp.txt")
    print("P2P running time with %d clients is :%f s"%(num,run_time))
    CLI(net)
    net.stop()


def main():
    number = input("请输入一个整数\n")
    number = int(number)
    create_topo(number)


if __name__ == '__main__':
    main()
