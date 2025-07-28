import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)

def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        if packet.haslayer(scapy.TCP):
            print(f"TCP Packet: {ip_src} -> {ip_dst}")
            if packet[scapy.TCP].flags == "S":
                print("[!] SYN Packet Detected!")
        elif packet.haslayer(scapy.UDP):
            print(f"UDP Packet: {ip_src} -> {ip_dst}")
        elif packet.haslayer(scapy.ICMP):
            print(f"ICMP Packet: {ip_src} -> {ip_dst}")

if __name__ == "__main__":
    interface = "eth0"
    sniff_packets(interface)
