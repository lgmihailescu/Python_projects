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
        log(a)
        
        #write_to_files((a.szone).lower(), (a.szone + "_testout.log").lower(), a.display_packet())

            
log_files = {}

def log(packet):
    if packet.szone not in log_files:
        log_files[packet.szone] = open(os.path.join(curr_dir, args.output, packet.szone + '.log'), 'a')
        print log_files
    log_files[packet.szone].write('%s\n' % packet.display_packet())
    log_files[packet.szone].flush()
    print packet.display_packet()
    print log_files




            
#def write_to_files(fzone,output_file,line):
#    if fzone in output_file:
#        out_file = open(os.path.join(curr_dir, args.output, output_file), 'a')
#        out_file.write('%s\n' % line)
#        out_file.flush()
#        out_file.close()
#        print line


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture DNS queries and output to specified directory')
    parser.add_argument('--output', '-o', help='write dumps to specified folder')

    args = parser.parse_args()
    print >> sys.stderr, 'Capturing DNS requests..'

    if args.output:
        os.mkdir(args.output)
        curr_dir = os.getcwd()
    else:
        out_file = None

    try:
        sniff(filter='port 53', prn=scanner, store=0)
    except KeyboardInterrupt:
        exit(0)
        
