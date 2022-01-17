from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import quietRun, dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from sys import argv
import time
# It would be nice if we didn't have to do this:
# # pylint: disable=arguments-differ
class SingleSwitchTopo( Topo ):
    def build( self ):
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')
        switch5 = self.addSwitch('s5')
        switch6 = self.addSwitch('s6')
        switch7 = self.addSwitch('s7')
        switch8 = self.addSwitch('s8')
        switch=self.addSwitch('s0')
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        host3=self.addHost('h3')
        host4=self.addHost('h4')
        host5=self.addHost('h5')
        host6=self.addHost('h6')
        host7=self.addHost('h7')
        host8=self.addHost('h8')
        self.addLink(host1, switch1, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host2, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host3, switch1, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host4, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host5, switch1, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host6, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host7, switch1, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(host8, switch2, bw=100, delay='5ms', loss=0, use_htb=True)
        self.addLink(switch1,switch2,bw=100,delay="5ms",loss=0,use_htb=True)
        # self.addLink(switch1, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch2, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch3, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch4, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch5, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch6, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch7, switch, bw=100, delay='5ms', loss=0, use_htb=True)
        # self.addLink(switch8, switch, bw=100, delay='5ms', loss=0, use_htb=True)

def Test(tcp):
    "Create network and run simple performance test"
    topo = SingleSwitchTopo()
    net = Mininet( topo=topo,host=CPULimitedHost, link=TCLink,autoStaticArp=False )
    net.start()
    info( "Dumping host connections\n" )
    dumpNodeConnections(net.hosts)    # set up tcp congestion control algorithm
    output = quietRun( 'sysctl -w net.ipv4.tcp_congestion_control=' + tcp )
    assert tcp in output
    info( "Testing bandwidth between h1 and h2 under TCP " + tcp + "\n" )
    h1, h2 ,h3,h4,h5,h6,h7,h8= net.getNodeByName('h1', 'h2','h3','h4','h5','h6','h7','h8')
    # _serverbw, clientbw = net.iperf( [ h1, h2 ], seconds=10 ,)
    # info( "h1 and h2 "+clientbw, '\n')
    # _serverbw, clientbw = net.iperf( [ h3, h4 ], seconds=10 )
    # info( "h3 and h4 "+clientbw, '\n')
    # _serverbw, clientbw = net.iperf( [ h5, h6 ], seconds=10 )
    # info( "h5 and h6 "+clientbw, '\n')
    # _serverbw, clientbw = net.iperf( [ h7, h8 ], seconds=10 )
    # info( "h7 and h8 "+clientbw, '\n')
    h1.cmd("iperf -s -p 5201 -i 1 > results &")
    print (h2.cmd("iperf -c 10.0.0.1 -p 5201 -t 10 &"))
    h3.cmd("iperf -s -p 5201 -i 1 > results3 &")
    print (h4.cmd("iperf -c 10.0.0.3 -p 5201 -t 10 &"))
    h5.cmd("iperf -s -p 5201 -i 1 > results5 &")
    print (h6.cmd("iperf -c 10.0.0.5 -p 5201 -t 10 &"))
    h7.cmd("iperf -s -p 5201 -i 1 > results7 &")
    print (h8.cmd("iperf -c 10.0.0.7 -p 5201 -t 10 "))
    CLI(net)

    net.stop()
if __name__ == '__main__':
    setLogLevel('info')    # pick a congestion control algorithm, for example, 'reno', 'cubic', 'bbr', 'vegas', 'hybla', etc.
    tcp = 'bbr'
    Test(tcp)