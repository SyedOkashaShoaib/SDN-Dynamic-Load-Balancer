#!/usr/bin/env python3
"""
SDN Layer 3 Router (Phase 3 - Complete)
Acts as a virtual gateway, rewrites MAC addresses, and uses 
mathematical topology logic to route packets without flooding.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, in_proto

class L3Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Router, self).__init__(*args, **kwargs)
        self.ROUTER_MAC = 'aa:bb:cc:dd:ee:ff'

        self.arp_table = {}
        host_global_counter = 1
        
        # Generates exact IP and MAC pairs matching the fat_tree.py generation
        for pod in range(4):
            subnet = pod + 1
            host_pod_counter = 1
            for i in range(4):
                ip = f'10.0.{subnet}.{host_pod_counter}'
                
                if pod < 2:
                    mac = f'00:00:00:00:00:{host_global_counter:02x}'
                else:
                    mac = f'00:00:00:00:01:{host_global_counter:02x}'
                
                self.arp_table[ip] = {'mac': mac, 'pod': pod}
                host_global_counter += 1
                host_pod_counter += 1

    def calculate_routing(self, dpid_str, dst_ip):
        """ The Mathematical Fat-Tree Routing Engine """
        layer = dpid_str[0]
        target_pod = int(dst_ip.split('.')[2]) - 1
        host_id = int(dst_ip.split('.')[3])

        if layer == '1': # Core Switch Layer
            return target_pod + 1
            
        elif layer == '2': # Aggregation Switch Layer
            current_pod = int(dpid_str[1])
            if current_pod == target_pod:
                edge_idx = (host_id - 1) // 2
                return edge_idx + 3
            else:
                return 1
                
        elif layer == '3': # Edge Switch Layer
            current_pod = int(dpid_str[1])
            
            # Identify if we are Edge switch 1 or 2
            current_edge_idx = int(dpid_str[3]) 
            # Identify if the target host lives on Edge 1 or 2
            target_edge_idx = ((host_id - 1) // 2) + 1 

            if current_pod == target_pod and current_edge_idx == target_edge_idx:
                # Host is on THIS specific edge switch. Route DOWN.
                return ((host_id - 1) % 2) + 3
            else:
                # Host is in another pod, OR on the other edge switch in this pod. Route UP.
                return 1
        return 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(msg, datapath, in_port, pkt, eth)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            self.handle_ipv4(msg, datapath, in_port, pkt, eth, ipv4_pkt)
            return

    def handle_arp(self, msg, datapath, in_port, pkt, eth):
        arp_pkt = pkt.get_protocols(arp.arp)[0]
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        dst_ip = arp_pkt.dst_ip

        # --- THE FIX: PROXY ARP ---
        # 1. Is the host asking for the Default Gateway?
        if dst_ip.endswith('.254'):
            reply_mac = self.ROUTER_MAC
            
        # 2. Is the host asking for another specific host in the same subnet?
        elif dst_ip in self.arp_table:
            reply_mac = self.arp_table[dst_ip]['mac']
            
        # 3. We don't know this IP. Drop it.
        else:
            return 

        # Construct the targeted ARP Reply
        reply_pkt = packet.Packet()
        reply_eth = ethernet.ethernet(dst=eth.src, src=reply_mac, ethertype=ether_types.ETH_TYPE_ARP)
        reply_arp = arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_mac, src_ip=dst_ip,
                            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
        
        reply_pkt.add_protocol(reply_eth)
        reply_pkt.add_protocol(reply_arp)
        reply_pkt.serialize()

        # Shoot the packet back to the host that asked
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
        datapath.send_msg(out)

    def handle_ipv4(self, msg, datapath, in_port, pkt, eth, ipv4_pkt):
        # 1. Is it for the gateway?
        if ipv4_pkt.dst.endswith('.254'):
            if ipv4_pkt.proto == in_proto.IPPROTO_ICMP:
                self.handle_icmp(msg, datapath, in_port, pkt, eth, ipv4_pkt)
            return

        # 2. It is for another host. Route it.
        dst_ip = ipv4_pkt.dst
        if dst_ip not in self.arp_table:
            return 

        # THE FATAL BUG FIX: Convert Ryu's integer DPID back into the exact Hex string we assigned in Mininet
        # e.g., 4097 -> '1001'
        dpid_hex = format(datapath.id, "x")
        
        # Fallback safeguard
        if len(dpid_hex) < 4:
            dpid_hex = dpid_hex.zfill(4)

        # Use math to figure out the port
        out_port = self.calculate_routing(dpid_hex, dst_ip)
        
        # --- NEW LOGGING: Watch the Brain Work ---
        self.logger.info("ROUTING: Switch %s | Dest IP: %s -> Sending out Port %s", dpid_hex, dst_ip, out_port)

        target_mac = self.arp_table[dst_ip]['mac']

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        actions = [
            parser.OFPActionSetField(eth_src=self.ROUTER_MAC),
            parser.OFPActionSetField(eth_dst=target_mac),
            parser.OFPActionOutput(out_port)
        ]

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
        
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 10, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_icmp(self, msg, datapath, in_port, pkt, eth, ipv4_pkt):
        icmp_pkt = pkt.get_protocols(icmp.icmp)[0]
        if icmp_pkt.type != icmp.ICMP_ECHO_REQUEST:
            return

        reply_pkt = packet.Packet()
        reply_eth = ethernet.ethernet(dst=eth.src, src=self.ROUTER_MAC, ethertype=ether_types.ETH_TYPE_IP)
        reply_ipv4 = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
        reply_icmp = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, 
                               csum=0, data=icmp_pkt.data)

        reply_pkt.add_protocol(reply_eth)
        reply_pkt.add_protocol(reply_ipv4)
        reply_pkt.add_protocol(reply_icmp)
        reply_pkt.serialize()

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
        datapath.send_msg(out)
