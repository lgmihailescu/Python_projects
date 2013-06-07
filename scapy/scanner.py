from scapy.all import *
#import scapy

def scanner(pkt):
    if IP in pkt:
        #and pkt[IP].proto == UDP:
        return pkt.sprintf("%IP.src%:%TCP.sport% >>> %IP.dst%:%TCP.dport%")

sniff(prn=scanner, filter="port 53", store=0)
