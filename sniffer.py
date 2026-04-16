from scapy.all import sniff, ARP, TCP, IP

#Gets all known hosts from the .txt file

known_hosts = open('known_hosts.txt', 'r').read().splitlines()

#capturing packets (specifically arp and tcp)
def process_packet(packet):
    if packet.haslayer(ARP):
        print(f'[ARP] {packet[ARP].psrc} → {packet[ARP].pdst}')
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"[TCP] {src_ip}:{src_port} → {dst_ip}:{dst_port}")

if __name__ == '__main__':
    print(f"[*] Monitoring traffic for {len(known_hosts)} hosts...")
    sniff(filter="arp or tcp", prn=process_packet, store=0, count=0)
