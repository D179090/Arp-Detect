from scapy.all import sniff

IP_MAC_MAP = {}

def processPacket(packet):
    src_IP = packet['ARP'].psrc
    src_MAC = packet['Ether'].src
    if src_MAC IP_MAC_MAP.keys():
        if IP_MAC_MAP.[src_MAC] != src_IP:
            try:
                old_ip = IP_MAC_MAP[src_MAC]
            except:
                old_IP = "unknown"
            mesage = ("\nPossible ARP attack detected!!!\n")
            return mesage 
    else:
        IP_MAC_MAP[src_MAC] = src_IP

sniff(count=0, filter="arp", store= 0, prn = processPacket)
