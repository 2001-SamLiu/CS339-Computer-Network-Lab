from os import wait
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether, ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4, arp
from ryu.lib.packet import icmp, tcp, udp
import time


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switch = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
         # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        if datapath.id == 1:  # the packets will be delivered to h1 from in_port 2

            self.send_group_mod(datapath)
            actions = [parser.OFPActionGroup(group_id=50)]
            match = parser.OFPMatch(in_port=3, eth_src='1e:0b:fa:73:69:f1')
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionOutput(3)]
            match = parser.OFPMatch(in_port=2,  eth_src='1e:0b:fa:73:69:f2')
            self.add_flow(datapath, 10, match, actions)
            match = parser.OFPMatch(in_port=1,eth_src='1e:0b:fa:73:69:f2')
            self.add_flow(datapath, 10, match, actions)
            self.switch[datapath.id] = datapath
            match = parser.OFPMatch(in_port=1,  eth_src='1e:0b:fa:73:69:f1')
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 10, match, actions)

        # switch s2
        if datapath.id == 2:

            # add the return flow for h2 in s2.
            # h2 is connected to port 3.
            self.send_group_mod(datapath)
            actions = [parser.OFPActionGroup(group_id=50)]
            match = parser.OFPMatch(in_port=3, eth_src='1e:0b:fa:73:69:f2')
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionOutput(3)]
            match = parser.OFPMatch(in_port=1, eth_src='1e:0b:fa:73:69:f1')
            self.add_flow(datapath, 10, match, actions)
            actions = [parser.OFPActionOutput(2)]
            match = parser.OFPMatch(in_port=1, eth_src='1e:0b:fa:73:69:f2')
            self.add_flow(datapath, 10, match, actions)
            actions = [parser.OFPActionOutput(3)]
            match = parser.OFPMatch(in_port=2, eth_src='1e:0b:fa:73:69:f1')
            self.add_flow(datapath, 10, match, actions)
            self.switch[datapath.id] = datapath
        # switch s3
        if datapath.id == 3:
            # h1 is connected to port 3.
            self.send_group_mod(datapath)
            actions = [parser.OFPActionGroup(group_id=52)]
            # actions = [parser.OFPActionOutput(2)]
            match = parser.OFPMatch(in_port=2, eth_src='1e:0b:fa:73:69:f2')
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionGroup(group_id=53)]
            match = parser.OFPMatch(in_port=1, eth_src='1e:0b:fa:73:69:f1')
            self.add_flow(datapath, 10, match, actions)
            self.switch[datapath.id] = datapath

        # # switch s4
        if datapath.id == 4:
            # h1 is connected to port 3.
            actions = [parser.OFPActionOutput(2)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionOutput(1)]
            match = parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)
            self.switch[datapath.id] = datapath

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        h1_mac = '1e:0b:fa:73:69:f1'
        h2_mac = '1e:0b:fa:73:69:f2'
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.logger.info("output port: %s", out_port)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info("ethertype:%s", eth.ethertype)
            # ether_type is ARP when using PINGALL
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                self.logger.info("protocol:%s", protocol)
                if protocol == in_proto.IPPROTO_ICMP:
                    matching = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                               ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    self.logger.info("icmp")
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    matching = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                               ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol,
                                               tcp_src=t.src_port, tcp_dst=t.dst_port)
                    self.logger.info("tcp")
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    matching = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                               ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol,
                                               udp_src=u.src_port, udp_dst=u.dst_port)
                    self.logger.info("udp")
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                ar = pkt.get_protocol(arp.arp)
                srcmac = ar.src_mac
                dstmac = ar.dst_mac
                srcip = ar.src_ip
                dstip = ar.dst_ip
                #     ic=pkt.get_protocol(icmp.icmp)
                #     t=pkt.get_protocol(tcp.tcp)
                #     u=pkt.get_protocol(udp.udp)
                #     if ic:
                #         matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                #                             eth_src=srcmac,ipv4_dst=dstip,ip_proto=2)
                #         self.logger.info("icmp")
                # # self.logger.info("protocol:%s",protocol)
                #     elif t:
                #         matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                #                                 ipv4_src=srcip,ipv4_dst=dstip,ip_proto=6,
                #                                 tcp_src=t.src_port,tcp_dst=t.dst_port)
                #         self.logger.info("tcp")
                #     elif u:
                #         matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                #                                 ipv4_src=srcip,ipv4_dst=dstip,ip_proto=17,
                #                                 udp_src=u.src_port,udp_dst=u.dst_port)
                #         self.logger.info("udp")
                #     else:
                #         matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                #                                 ipv4_src=srcip,ipv4_dst=dstip)
                matching = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, matching, actions, msg.buffer_id)
                    self.logger.info("add flow from %s to %s in %s", src, dst, in_port)
                    return
                else:
                    self.logger.info("add flow from %s to %s in %s", src, dst, in_port)
                    self.add_flow(datapath, 1, matching, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def send_group_mod(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # group 1
        # watch_port=ofproto_v1_3.OFPP_ANY
        # watch_group=ofproto_v1_3.OFPG_ANY
        actions1 = [parser.OFPActionOutput(1)]
        actions2 = [parser.OFPActionOutput(2)]
        buckets = [parser.OFPBucket(watch_port=1, actions=actions1),
                   parser.OFPBucket(watch_port=2, actions=actions2)]

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_FF, 50, buckets=buckets)
        datapath.send_msg(req)

        actions1 = [parser.OFPActionOutput(2)]
        actions2 = [parser.OFPActionOutput(1)]
        buckets = [parser.OFPBucket(watch_port=2, actions=actions1),
                   parser.OFPBucket(watch_port=1, actions=actions2)]

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_FF, 51, buckets=buckets)
        datapath.send_msg(req)
        OFPP_IN_PORT=0xfffffff8
        actions1 = [parser.OFPActionOutput(1)]
        actions2 = [parser.OFPActionOutput(OFPP_IN_PORT)]
        buckets = [parser.OFPBucket(watch_port=1, actions=actions1),
                   parser.OFPBucket(watch_port=2, actions=actions2)]

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_FF, 52, buckets=buckets)
        datapath.send_msg(req)

        actions1 = [parser.OFPActionOutput(2)]
        actions2 = [parser.OFPActionOutput(OFPP_IN_PORT)]
        buckets = [parser.OFPBucket(watch_port=2, actions=actions1),
                   parser.OFPBucket(watch_port=1, actions=actions2)]

        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
                                 ofproto.OFPGT_FF, 53, buckets=buckets)
        datapath.send_msg(req)
        #output_port is 2
        # actions1=[parser.OFPActionOutput(2)]
        # actions2 = [parser.OFPActionOutput(1)]
        # buckets = [parser.OFPBucket(weight1, watch_port, watch_group, actions=actions1),
        # parser.OFPBucket(weight2, watch_port, watch_group, actions=actions2)]

        # req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
        #                          ofproto.OFPGT_FF, 51, buckets)
        # datapath.send_msg(req)
