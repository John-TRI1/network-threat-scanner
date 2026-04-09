"""
Network Threat Scanner - Layered Discovery Module

This module performs layered network discovery using multiple scanning techniques:
- Layer 1: ICMP Ping Sweep - Discovers hosts that respond to ICMP echo requests
- Layer 2: ARP Scan - Discovers hosts on the local network segment via ARP requests
- Layer 3: TCP SYN Scan - Can discover hosts with ICMP and ARP disabled by probing common TCP ports

The layered approach ensures comprehensive host discovery while minimizing false negatives.
"""

from scapy.all import ARP, Ether, srp, IP, ICMP, sr, TCP, sr1
import ipaddress
import sys
from ping3 import ping
from multiprocessing import Pool

# Layer 1: ICMP PING SWEEP
# Create ICMP packet and send it to the network and see which devices respond
# This is the first layer of discovery - fast but may miss hosts with ICMP disabled

def ping_sweep(ip):
    """
    Perform ICMP ping sweep on a single IP address.

    Args:
        ip (str): The IP address to ping

    Returns:
        str or None: The IP address if alive, None otherwise
    """
    response = ping(ip, timeout=1, size=56)
    if response is not None and response is not False:
        print(f'{ip} IS ALIVE, FOUND VIA ICMP (RTT:{response:.4f}s)')
        return ip
    else:
        pass

# Layer 2: ARP-SCAN
# ARP scanning works on the local network segment and can discover hosts
# that don't respond to ICMP but are active on the LAN

def arp_scan(ip):
    """
    Perform ARP scan on a single IP address.

    Args:
        ip (str): The IP address to ARP scan

    Returns:
        str or None: The IP address if alive, None otherwise
    """
    arp = ARP(pdst=ip)
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')  # Broadcast Ethernet frame
    packet = ether/arp  # Combine Ethernet and ARP layers
    result = srp(packet, timeout=1, verbose=0)[0]

    for sent, received in result:
        print(f'{received.psrc} IS ALIVE, FOUND VIA ARP')
        return received.psrc
    return None


if __name__ == '__main__':
    # Main execution block - performs layered network discovery

    # Get target network from user input
    target_ip = input(f'Enter the IP address you want to scan: ')

    # Generate list of all host IPs in the target network
    ip_list = [str(ip) for ip in ipaddress.ip_network(target_ip, strict=False).hosts()]

    # Layer 1: ICMP Ping Sweep
    # Use multiprocessing to speed up the ping sweep across all IPs
    with Pool() as pool:
        results = pool.map(ping_sweep,  ip_list)
        alive = [ip for ip in results if ip is not None]
    print(f'\n{len(alive)} IP FOUND VIA ICMP')

    # Layer 2: ARP Scan
    # Scan remaining IPs (those not found by ICMP) with ARP
    remaining = [ip for ip in ip_list if ip not in alive]
    with Pool() as pool:
        arp_results = pool.map(arp_scan, remaining)
        arp_alive = [ip for ip in arp_results if ip is not None]
    print(f'\n{len(arp_alive)} IP FOUND VIA ARP-SCAN')

    # Combine results and remove duplicates
    all_alive = sorted(set(alive) | set(arp_alive))
    print(f'\n{len(all_alive)} TOTAL UNIQUE HOST FOUND')
    for ip in all_alive:
        print(f'{ip}')
