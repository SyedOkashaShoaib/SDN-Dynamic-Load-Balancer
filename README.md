# SDN Dynamic Load Balancer

A small SDN project that load-balances traffic across a pool of backend servers using a Ryu controller, running on a simulated fat-tree network in Mininet, with a dashboard to watch which server is getting picked.

## What it does

Clients send traffic to a single virtual IP (`10.0.0.100`). The Ryu controller catches the first packet of each new connection, checks which of the four backend servers currently has the least load, and rewrites the packet to send it there instead. Replies get rewritten back so they look like they came from the virtual IP.

It also answers ARP and ICMP directly (so there's no real host needed behind the virtual IP), and routes normal traffic through the fat-tree topology based on each switch's position in the tree.

Server load is tracked with a simple counter — it goes up when a server is picked and decays over time in the background, so the balancing decision can change as things go on. An HTML dashboard polls a `/metrics` endpoint the controller exposes and shows the load on each server as a bar chart.

## Structure

```
SDN-Dynamic-Load-Balancer/
├── controller/
│   ├── simple_switch.py   # basic L2 learning switch, used to test the topology first
│   ├── l3_router.py       # main controller: routing, load balancing, REST API
│   └── load_balancer.py   # empty for now, logic currently lives in l3_router.py
├── topology/
│   ├── mini.py             # small 2-host topology for testing
│   └── fat_tree.py         # the k=4 fat-tree topology, plus a script to auto-generate traffic
├── dashboard.html          # load chart
└── requirements.txt
```
##What's next?
Nothing really.. 

## Built with

Ryu (OpenFlow 1.3), Mininet + Open vSwitch, WebOb for the REST endpoint, Chart.js for the dashboard, iperf for generating traffic.

## Running it

Needs Mininet, Open vSwitch, and Ryu on Linux (usually easiest in a VM).
