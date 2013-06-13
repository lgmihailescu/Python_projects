#!/usr/bin/env python

import os
import datetime
import argparse
import whois
import sys


from scapy.all import *

class Packet:
    def __init__(self, time, ipdst, port, sname, szone, qtype):
        self.time = str(time)
        self.ipdst = str(ipdst)
        self.sname = str(sname)
        self.szone = str(szone)
        self.qtype = str(qtype)
        self.port = str(port)
        
    def display_packet(self):
        return self.time + "    " + self.ipdst + "    " + self.port + "    " + self.sname + "    " + self.szone + "    " + self.qtype
           

def scanner(pkt):
    if pkt.haslayer(DNSQR):
        q = pkt.getlayer(DNSQR)
        tokens = ('.' + q.qname.rstrip('.')).rsplit('.', 2)
        name , zone = tokens[0].lstrip('.'), '.'.join(tokens[-2:])
        timestamp = datetime.datetime.utcnow().replace(microsecond=0)
        sname=name or '@'
        szone=zone
        qtype=q.sprintf('%qtype%')
        ipdst=pkt.sprintf('%IP.dst%')
        port=pkt.sprintf('%UDP.dport%')

        a = Packet(timestamp,ipdst,port,sname,szone,qtype)

        if out_file:
            out_file.write('%s\n' % a.display_packet())
            out_file.flush()
            print a.display_packet()
        else:
            print a.display_packet()
            

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture DNS queries and output to specified directory')
    parser.add_argument('--output', '-o', help='write dumps to specified folder')

    args = parser.parse_args()
    print >> sys.stderr, 'Capturing DNS requests..'

    if args.output:
        os.mkdir(args.output)
        curr_dir = os.getcwd()
        out_file = open(os.path.join(curr_dir, args.output,"testfile.log"), 'a')
    else:
        out_file = None

    try:
        sniff(filter='port 53', prn=scanner, store=0)
    except KeyboardInterrupt:
        exit(0)
    finally:
        if out_file:
            out_file.close()
