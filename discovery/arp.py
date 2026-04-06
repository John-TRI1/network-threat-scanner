from scapy.all import ARP, Ether, srp 

target_ip = '144.167.112.108' #target ip 

arp = ARP(pdst=target_ip) #create arp packet

ether = Ether(dst='ff:ff:ff:ff:ff:ff') #create ether broadcast packet, mac address indicates broadcasting
packet = ether/arp #stack them 

result = srp(packet, timeout=3)[0] #send and recveive packet at layer 2, set a timeout so script does not get stuck

#list of client that will be filled in the loop below
clients=[]

for sent, received in result: 
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
#print clients
print(f'Available devices on the network')
print(f'IP' + ' '*18+'mac')

for client in clients:
    print("{:16}  {}".format(client['ip'], client['mac']))