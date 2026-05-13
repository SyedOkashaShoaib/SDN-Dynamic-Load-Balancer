#!/usr/bin/env python3
"""
CS4068 SDN Load Balancer - Phase 4: Round Robin Server Load Balancing (Baseline)
Integrates a Virtual IP (VIP), IP Header Rewriting (NAT), and a Round Robin selection algorithm.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp, in_proto
from ryu.lib import hub
class L3Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Router, self).__init__(*args, **kwargs)
        self.ROUTER_MAC = 'aa:bb:cc:dd:ee:ff'

        self.VIP = '10.0.0.100' 
        self.SERVER_POOL = ['10.0.3.1', '10.0.3.2', '10.0.4.1', '10.0.4.2']
        
        # --- NEW: DYNAMIC METRICS TRACKER ---
        # Initialize all servers with 0 load
        self.server_load = {server: 0 for server in self.SERVER_POOL}
        
        # Spawn a background thread that runs independently of packet processing
        self.monitor_thread = hub.spawn(self._monitor_server_load)

        self.arp_table = {}
        host_global_counter = 1
        
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

    def _monitor_server_load(self):
        """ Background Thread: Simulates connection decay and prints a live load dashboard """
        while True:
            hub.sleep(5) # Run every 5 seconds
            
            self.logger.info("=== [LIVE SERVER METRICS] ===")
            for server in self.SERVER_POOL:
                # Decay the load by 1 (minimum 0) to simulate finished requests
                if self.server_load[server] > 0:
                    self.server_load[server] -= 1
                
                self.logger.info("Server: %s | Current Active Load: %s", server, self.server_load[server])
            self.logger.info("=============================")

    def calculate_routing(self, dpid_str, src_ip, dst_ip):
        """ The 100% ECMP Load Balancer Routing Engine """
        layer = dpid_str[0]
        target_pod = int(dst_ip.split('.')[2]) - 1
        host_id = int(dst_ip.split('.')[3])

        src_last_octet = int(src_ip.split('.')[3])
        dst_last_octet = int(dst_ip.split('.')[3])
        uplink_port = ((src_last_octet + dst_last_octet) % 2) + 1

        if layer == '1': 
            return target_pod + 1
            
        elif layer == '2': 
            current_pod = int(dpid_str[1])
            if current_pod == target_pod:
                edge_idx = (host_id - 1) // 2
                return edge_idx + 3
            else:
                return uplink_port 
                
        elif layer == '3': 
            current_pod = int(dpid_str[1])
            current_edge_idx = int(dpid_str[3]) 
            target_edge_idx = ((host_id - 1) // 2) + 1 

            if current_pod == target_pod and current_edge_idx == target_edge_idx:
                return ((host_id - 1) % 2) + 3
            else:
                return uplink_port 
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

        # NEW: Answer ARP requests for the Virtual IP
        if dst_ip == self.VIP:
            reply_mac = self.ROUTER_MAC
            self.logger.info("ARP Proxy: Intercepted request for Virtual IP %s", dst_ip)
        elif dst_ip.endswith('.254'):
            reply_mac = self.ROUTER_MAC
        elif dst_ip in self.arp_table:
            reply_mac = self.arp_table[dst_ip]['mac']
        else:
            return 

        reply_pkt = packet.Packet()
        reply_eth = ethernet.ethernet(dst=eth.src, src=reply_mac, ethertype=ether_types.ETH_TYPE_ARP)
        reply_arp = arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_mac, src_ip=dst_ip,
                            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip)
        
        reply_pkt.add_protocol(reply_eth)
        reply_pkt.add_protocol(reply_arp)
        reply_pkt.serialize()

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
        datapath.send_msg(out)

    def handle_ipv4(self, msg, datapath, in_port, pkt, eth, ipv4_pkt):
        if ipv4_pkt.dst.endswith('.254'):
            if ipv4_pkt.proto == in_proto.IPPROTO_ICMP:
                self.handle_icmp(msg, datapath, in_port, pkt, eth, ipv4_pkt)
            return

        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid_hex = format(datapath.id, "x").zfill(4)

        # ---------------------------------------------------------
        # SCENARIO A: Client is sending traffic TO the Virtual IP
        # ---------------------------------------------------------
        if dst_ip == self.VIP:
            # --- THE DYNAMIC ALGORITHM: Least-Loaded Server ---
            # Find the server in the pool with the minimum current load value
            selected_server = min(self.server_load, key=self.server_load.get)
            
            # Artificially spike the load for this server by 3 so the algorithm 
            # is forced to pick a different server for the next immediate request
            self.server_load[selected_server] += 3
            
            target_mac = self.arp_table[selected_server]['mac']
            out_port = self.calculate_routing(dpid_hex, src_ip, selected_server)
            
            self.logger.info("DYNAMIC SLB: VIP Request from %s routed to Least-Loaded Server %s (Load spiked to %s)", 
                             src_ip, selected_server, self.server_load[selected_server])

            actions = [
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionSetField(ipv4_dst=selected_server),
                parser.OFPActionOutput(out_port)
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=self.VIP)

        # ---------------------------------------------------------
        # SCENARIO B: Server is replying back to a Client
        # ---------------------------------------------------------
        elif src_ip in self.SERVER_POOL and dst_ip not in self.SERVER_POOL and dst_ip != self.VIP:
            target_mac = self.arp_table[dst_ip]['mac']
            out_port = self.calculate_routing(dpid_hex, src_ip, dst_ip)

            # SOURCE NAT: Rewrite the source IP so it looks like the VIP replied
            actions = [
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionSetField(ipv4_src=self.VIP),
                parser.OFPActionOutput(out_port)
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)

        # ---------------------------------------------------------
        # SCENARIO C: Normal Host-to-Host network traffic
        # ---------------------------------------------------------
        elif dst_ip in self.arp_table:
            target_mac = self.arp_table[dst_ip]['mac']
            out_port = self.calculate_routing(dpid_hex, src_ip, dst_ip)
            
            actions = [
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionOutput(out_port)
            ]
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        else:
            return # Drop unknown IPs

        # Install the flow and forward the packet
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 10, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 10, match, actions)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
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
