from scapy.all import *
dest_ip = "10.42.42.113"
ethr_src="01:02:03:04:05:06"
src_ip= "10.42.42.118"
sendp(Ether(src=ethr_src)/IP(dst=dest_ip,src=src_ip,len=442)/ICMP())

