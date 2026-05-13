#!/usr/bin/env python3
"""
SDN-Based Dynamic Load Balancer - Layer 3 Data Plane
Implementation of a k=4 Fat-Tree Topology (20 Switches) with Subnet Isolation.
Link creation separated chronologically to guarantee deterministic OpenFlow Port numbering.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
class L3FatTreeTopo(Topo):
    def build(self):
        k = 4
        core_switches = []
        agg_switches = []
        edge_switches = []

        info("*** Adding Core Switches\n")
        for i in range((k//2)**2):
            dpid_hex = f'100{i+1}'
            sw = self.addSwitch(f'c{i+1}', cls=OVSSwitch, protocols='OpenFlow13', dpid=dpid_hex)
            core_switches.append(sw)

        info("*** Adding Aggregation and Edge Switches\n")
        for pod in range(k):
            for i in range(k//2):
                agg_dpid = f'2{pod}0{i+1}'
                agg_sw = self.addSwitch(f'a{pod}_{i}', cls=OVSSwitch, protocols='OpenFlow13', dpid=agg_dpid)
                agg_switches.append(agg_sw)
                
                edge_dpid = f'3{pod}0{i+1}'
                edge_sw = self.addSwitch(f'e{pod}_{i}', cls=OVSSwitch, protocols='OpenFlow13', dpid=edge_dpid)
                edge_switches.append(edge_sw)

        info("*** 1. Cabling Aggregation to Core (Assigns Agg Ports 1 & 2, Core Ports 1, 2, 3, 4)\n")
        for pod in range(k):
            for agg_idx in range(k//2):
                agg = agg_switches[pod*(k//2) + agg_idx]
                # Core switches are grouped. Group i connects to Agg i in all pods.
                for core_idx in range(k//2):
                    core = core_switches[agg_idx * (k//2) + core_idx]
                    self.addLink(agg, core, bw=1000, delay='1ms')

        info("*** 2. Cabling Edge to Aggregation (Assigns Edge Ports 1 & 2, Agg Ports 3 & 4)\n")
        for pod in range(k):
            pod_aggs = agg_switches[pod*(k//2) : (pod+1)*(k//2)]
            pod_edges = edge_switches[pod*(k//2) : (pod+1)*(k//2)]
            for edge in pod_edges:
                for agg in pod_aggs:
                    self.addLink(edge, agg, bw=100, delay='5ms')

        info("*** 3. Cabling Hosts to Edge (Assigns Edge Ports 3 & 4)\n")
        host_global_counter = 1
        for pod in range(k):
            pod_subnet = pod + 1       
            host_pod_counter = 1       
            gateway_ip = f'10.0.{pod_subnet}.254' 
            
            for i in range(k//2):
                edge_sw = edge_switches[pod*(k//2) + i]
                for j in range(k//2):
                    host_ip = f'10.0.{pod_subnet}.{host_pod_counter}/24'
                    
                    if pod < 2:
                        h_name = f'h{pod}_{host_global_counter}'
                        mac_addr = f'00:00:00:00:00:{host_global_counter:02x}'
                    else:
                        h_name = f's{pod}_{host_global_counter}'
                        mac_addr = f'00:00:00:00:01:{host_global_counter:02x}'

                    h = self.addHost(h_name, ip=host_ip, mac=mac_addr, defaultRoute=f'via {gateway_ip}')
                    self.addLink(h, edge_sw, bw=10, delay='10ms')
                    
                    host_global_counter += 1
                    host_pod_counter += 1

# --- AUTOMATION SCRIPT ---
def automated_demo(net):
    print("\n" + "="*60)
    print(" SYSTEM AUTOMATION: DYNAMIC LOAD BALANCER STRESS TEST")
    print(" Press [Ctrl+C] at any time to halt the loop and enter CLI.")
    print("="*60)
    
    clients = [net.get('h0_1'), net.get('h0_2'), net.get('h0_3'), net.get('h0_4')]
    servers = [net.get('s2_9'), net.get('s2_10'), net.get('s3_13'), net.get('s3_14')]

    print("\n[INIT] Booting Backend TCP Listeners")
    print("[EXEC] Running 'iperf -s &' on s2_9, s2_10, s3_13, s3_14")
    for server in servers:
        server.cmd('iperf -s &')
    
    print("[PAUSE] 5 seconds: Allowing TCP daemons to initialize.\n")
    time.sleep(5)

    iteration = 1
    try:
        while True:
            print(f"\n--- BEGIN TEST ITERATION {iteration} ---")
            
            # --- SINGLE REQUEST ROUTING ---
            print("[PHASE 1] Single Request Routing")
            print("[EXEC] h0_1 executing: 'iperf -c 10.0.0.100 -t 3 &'")
            clients[0].cmd('iperf -c 10.0.0.100 -t 3 &')
            
            print("[PAUSE] 10 seconds: Waiting 3s for TCP transfer completion and 7s for server load metrics to decay to 0.")
            time.sleep(10)

            # --- CONCURRENT FLASH CROWD ---
            print("\n[PHASE 2] Concurrent 'Flash Crowd' Stress Test")
            print("[EXEC] h0_1, h0_2, h0_3, h0_4 simultaneously executing: 'iperf -c 10.0.0.100 -t 5 &'")
            for client in clients:
                client.cmd('iperf -c 10.0.0.100 -t 5 &')
                
            print("[PAUSE] 15 seconds: Waiting 5s for TCP transfers completion and 10s for server load metrics to decay to 0.")
            time.sleep(15)

            print(f"--- END TEST ITERATION {iteration} ---\n")
            iteration += 1

    except KeyboardInterrupt:
        # --- GRACEFUL EXIT ---
        print("\n\n[!] Interrupt Signal (Ctrl+C) Detected.")
        print("[CLEANUP] Terminating all background iperf TCP sockets to prevent Mininet zombie processes...")
        
        for server in servers:
            server.cmd('killall -9 iperf')
        for client in clients:
            client.cmd('killall -9 iperf')
            
        print("[CLEANUP] TCP environment sanitized.")
        print("="*60)
        print(" Dropping to manual Mininet CLI.")
        print("="*60)


# --- TOPOLOGY EXECUTION ---
def run_topology():
    topo = L3FatTreeTopo() 
    net = Mininet(topo=topo, build=False, link=TCLink, switch=OVSSwitch)
    info("*** Adding Controller\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    info("*** Building Network\n")
    net.build()  
    info("*** Starting Network\n")
    net.start()
    
    # Trigger the automated infinite loop
    automated_demo(net)
    
    # Opens the command line only AFTER the user hits Ctrl+C
    CLI(net)     
    info("*** Stopping Network\n")
    net.stop()   

if __name__ == '__main__':
    setLogLevel('info')
    run_topology()
    
    
    
    
