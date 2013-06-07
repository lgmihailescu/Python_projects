from scapy.all import *


def scanner(pkt):
    if IP in pkt:
        if UDP in pkt:
            return pkt.sprintf("%IP.src%:%UDP.sport% >>> %IP.dst%:%UDP.dport% -- query %DNS(DNSQR.qtype)%")

sniff(prn=scanner, filter=None, store=0)
