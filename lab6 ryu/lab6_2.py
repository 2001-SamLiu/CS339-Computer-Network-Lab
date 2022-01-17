from sys import setswitchinterval
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether, ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4,arp
from ryu.lib.packet import icmp,tcp,udp
import time 


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switch={}
        self.begin_time_s1=time.time()
        self.begin_time_s2=time.time()
        self.current_time_s1=0
        self.current_time_s2=0
        self.path_s1=0
        self.path_s2=0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev,path1=1,path2=0):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switch[datapath.id]=datapath
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
        if datapath.id == 1 and path1:
            # add group tables
            # self.send_group_mod(datapath)
            # actions = [parser.OFPActionGroup(group_id=50)]
            actions = [parser.OFPActionOutput(1)]
            match=parser.OFPMatch(in_port=3)
            self.add_flow(datapath, 10, match, actions)

            #add the return flow for h1 in s1.  
            # h1 is connected to port 3.
            # actions = [parser.OFPActionGroup(group_id=52)]
            actions = [parser.OFPActionOutput(3)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)
        # switch s2
        if datapath.id == 2 and path1:
        # add group tables
            # self.send_group_mod(datapath)
            # actions = [parser.OFPActionGroup(group_id=50)]
            actions = [parser.OFPActionOutput(1)]
            match = parser.OFPMatch(in_port=3)
            self.add_flow(datapath, 10, match, actions)


            #add the return flow for h2 in s2.  
            # h2 is connected to port 3.
            # actions = [parser.OFPActionGroup(group_id=52)]
            actions = [parser.OFPActionOutput(3)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)


        # switch s3
        if datapath.id == 3 and path1:
            # h1 is connected to port 3.
            actions = [parser.OFPActionOutput(2)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionOutput(1)]
            match = parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)
        
        if datapath.id == 4 and path1:
        # h1 is connected to port 3.
            actions = [parser.OFPActionOutput(2)]
            match = parser.OFPMatch(in_port=1)
            self.add_flow(datapath, 10, match, actions)

            actions = [parser.OFPActionOutput(1)]
            match = parser.OFPMatch(in_port=2)
            self.add_flow(datapath, 10, match, actions)
        # time.sleep(5)
            # print(path1,path2)
        if len(self.switch)==4:
            while True:
                time.sleep(5)
                self.logger.info("path2")
                # self.send_group_mod(datapath)
                actions = [parser.OFPActionOutput(2)]
                # actions = [parser.OFPActionOutput(1)]
                datapath=self.switch[1]
                match = parser.OFPMatch(in_port=3)
                self.del_flow(datapath,match)
                self.add_flow(datapath, 10, match, actions)

                #add the return flow for h1 in s1.  
                # h1 is connected to port 3.
                actions = [parser.OFPActionOutput(3)]                    
                match = parser.OFPMatch(in_port=1)
                self.del_flow(datapath,match)
                match = parser.OFPMatch(in_port=2)
                self.add_flow(datapath, 10, match, actions)


                datapath=self.switch[2]
                actions = [parser.OFPActionOutput(2)]
                match = parser.OFPMatch(in_port=3)
                self.del_flow(datapath,match)
                self.add_flow(datapath, 10, match, actions)


                #add the return flow for h2 in s2.  
                # h2 is connected to port 3.
                # actions = [parser.OFPActionGroup(group_id=52)]
                actions = [parser.OFPActionOutput(3)]
                match = parser.OFPMatch(in_port=1,)
                self.del_flow(datapath,match)
                match = parser.OFPMatch(in_port=2)
                self.add_flow(datapath, 10, match, actions)

                time.sleep(5)
                self.logger.info("path1")
                # self.send_group_mod(datapath)
                actions = [parser.OFPActionOutput(1)]
                # actions = [parser.OFPActionOutput(1)]


                datapath=self.switch[1]
                match = parser.OFPMatch(in_port=3)
                self.del_flow(datapath,match)
                self.add_flow(datapath, 10, match, actions)

                #add the return flow for h1 in s1.  
                # h1 is connected to port 3.
                actions = [parser.OFPActionOutput(3)]                    
                match = parser.OFPMatch(in_port=2)
                self.del_flow(datapath,match)
                match = parser.OFPMatch(in_port=1)
                self.add_flow(datapath, 10, match, actions)

                
                datapath=self.switch[2]
                actions = [parser.OFPActionOutput(1)]
                match = parser.OFPMatch(in_port=3)
                self.del_flow(datapath,match)
                self.add_flow(datapath, 10, match, actions)


                #add the return flow for h2 in s2.  
                # h2 is connected to port 3.
                # actions = [parser.OFPActionGroup(group_id=52)]
                actions = [parser.OFPActionOutput(3)]
                match = parser.OFPMatch(in_port=2)
                self.del_flow(datapath,match)
                match = parser.OFPMatch(in_port=1)
                self.add_flow(datapath, 10, match, actions)    
    def del_flow(self, datapath, match,buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     match=match,out_port=ofproto.OFPP_ANY,
                                     out_group=ofproto.OFPG_ANY,command=ofproto.OFPFC_DELETE,
                                    )
        else:
            mod = parser.OFPFlowMod(datapath=datapath, out_port=ofproto.OFPP_ANY,
                                     out_group=ofproto.OFPG_ANY,command=ofproto.OFPFC_DELETE,
                                    match=match,)
        datapath.send_msg(mod)

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
        self.current_time_s1=self.current_time_s2=time.time()
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
        # if(src==h1_mac and dst==h2_mac)\
        #             or (src==h2_mac and dst==h1_mac):
        #     if dpid==1:
        #         if in_port==1:
        #             out_port=2
        #         else :
        #             out_port=1
        #     if dpid==2 or dpid==3:
        #         if in_port==1:
        #             out_port=2
        #         else:
        #             out_port=1
        #     if dpid==4:
        #         if in_port==4:
        #             out_port=1
        #         else:
        #             out_port=4
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.logger.info("output port: %s",out_port)
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info("ethertype:%s",eth.ethertype)
            #ether_type is ARP when using PINGALL
            if eth.ethertype==ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip=ip.src
                dstip=ip.dst
                protocol=ip.proto
                self.logger.info("protocol:%s",protocol)
                if protocol==in_proto.IPPROTO_ICMP:
                    matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,ipv4_dst=dstip,ip_proto=protocol)
                    self.logger.info("icmp")
                elif protocol==in_proto.IPPROTO_TCP:
                    t= pkt.get_protocol(tcp.tcp)
                    matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,ipv4_dst=dstip,ip_proto=protocol,
                                            tcp_src=t.src_port,tcp_dst=t.dst_port)
                    self.logger.info("tcp")
                elif protocol==in_proto.IPPROTO_UDP:
                    u=pkt.get_protocol(udp.udp)
                    matching=parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=srcip,ipv4_dst=dstip,ip_proto=protocol,
                                            udp_src=u.src_port,udp_dst=u.dst_port)
                    self.logger.info("udp")
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if eth.ethertype==ether_types.ETH_TYPE_ARP:
                ar = pkt.get_protocol(arp.arp)
                srcmac=ar.src_mac
                dstmac=ar.dst_mac
                srcip=ar.src_ip
                dstip=ar.dst_ip
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
                    self.logger.info("add flow from %s to %s in %s",src,dst,in_port)
                    return
                else:
                    self.logger.info("add flow from %s to %s in %s",src,dst,in_port)
                    self.add_flow(datapath, 1, matching, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    # def send_group_mod(self,datapath):
    #     ofproto=datapath.ofproto
    #     parser=datapath.ofproto_parser
    #     # output_port is 1
    #     weight1=50
    #     weight2=50
    #     watch_port=ofproto_v1_3.OFPP_ANY
    #     watch_group=ofproto_v1_3.OFPQ_ALL
    #     actions = [parser.OFPActionOutput(1)]
    #     buckets = [parser.OFPBucket(weight1, watch_port, watch_group, actions=actions)]
        
    #     req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
    #                              ofproto.OFPGT_SELECT, 50, buckets)
    #     datapath.send_msg(req)
    #     #output_port is 2
    #     actions=[parser.OFPActionOutput(2)]
    #     buckets = [parser.OFPBucket(weight1, watch_port, watch_group, actions=actions)]
        
    #     req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
    #                              ofproto.OFPGT_SELECT, 51, buckets)
    #     datapath.send_msg(req)
    #     # output_port is 3
    #     actions=[parser.OFPActionOutput(3)]
    #     buckets = [parser.OFPBucket(weight1, watch_port, watch_group, actions=actions)]
        
    #     req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD,
    #                              ofproto.OFPGT_SELECT, 52, buckets)
    #     datapath.send_msg(req)