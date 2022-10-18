import scapy.all as scapy
import argparse
import itertools
import datetime

inactive = 10
active = 60

packet_list = []
flows = []

def process_packet(packet: scapy.Packet):
    if scapy.TCP in packet or scapy.UDP in packet or scapy.ICMP in packet:
        packet_list.append(packet)
    else:
        print("How? Packet:")
        print(packet.show())

def create_flows_from_packets(packets):
    global flows
    packets = list(packets)

    flow = []
    for packet in packets:
        if len(flow) == 0 or (flow[-1].time + inactive >= packet.time and flow[0].time + active >= packet.time):
            flow.append(packet)
        else:
            flows.append(flow)
            flow = [packet]
        if (scapy.TCP in packet and packet[scapy.TCP].flags & 1) > 0 or (scapy.TCP in packet and packet[scapy.TCP].flags & (1 << 2)) > 0:
            flows.append(flow)
            flow = []

    if len(flow) != 0:
        flows.append(flow)

def print_flow(packets):
    packet = packets[0]
    proto = packet[scapy.IP].proto

    packets = list(packets)
    packets.sort(key=lambda x: x.time)
    print(datetime.datetime.utcfromtimestamp(float(packets[0].time)), end="\t")
    print("ICMP" if proto == 1 else "TCP" if proto == 6 else "UDP", end="\t")

    sport = str(packet[scapy.TCP].sport) if proto == 6 else str(packet[scapy.UDP].sport) if proto == 17 else "0"
    dport = str(packet[scapy.TCP].dport) if proto == 6 else str(packet[scapy.UDP].dport) if proto == 17 else str(packet[scapy.ICMP].type) + "." + str(packet[scapy.ICMP].code)
    
    print(packets[0][scapy.IP].src + ":" + sport, end="\t")
    print("->", end="\t")
    print(packets[0][scapy.IP].dst + ":" + dport, end="\t")
    print(sum(map(lambda packet: packet[scapy.IP].len, packets)))

# Script
parser = argparse.ArgumentParser(description='Get netflows from pcap file')
parser.add_argument('-f', dest='file', action='store', help='pcap file', required=True)
parser.add_argument('-a', dest='active', action='store', help='active timeout', required=False, default=60)
parser.add_argument('-i', dest='inactive', action='store', help='inactive timeout', required=False, default=10)

args = parser.parse_args()

active = args.active
inactive = args.inactive

scapy.sniff(offline=args.file, filter="icmp or udp or tcp", prn=process_packet,store=0)

flow_key = lambda packet: (
    packet[scapy.IP].src, 
    packet[scapy.IP].dst,
    packet[scapy.IP].tos,
    packet[scapy.IP].proto,
    packet[scapy.TCP].sport if packet[scapy.IP].proto == 6 else packet[scapy.UDP].sport if packet[scapy.IP].proto == 17 else 0,
    packet[scapy.TCP].dport if packet[scapy.IP].proto == 6 else packet[scapy.UDP].dport if packet[scapy.IP].proto == 17 else packet[scapy.ICMP].type * 256 + packet[scapy.ICMP].code
    )

# itertools.groupby requires list to be sorted by the key
packet_list.sort(key=flow_key)
groups = itertools.groupby(packet_list, key=flow_key)

for key, group in groups:
    create_flows_from_packets(group)

flows.sort(key= lambda flow: flow[0].time)

for flow in flows:
    print_flow(flow)

print("Total flows: " + str(len(flows)))
print("Total packets: " + str(len(packet_list)))


