#!/usr/bin/env python

import datetime
import argparse

from scapy.all import *

class Packet:
    def __init__(self, time, ipdst, sname, szone, qtype):
        self.time = str(time)
        self.ipdst = str(ipdst)
        self.sname = str(sname)
        self.szone = str(szone)
        self.qtype = str(qtype)
        
    def displayPacket(self):
        return self.time + "    " + self.ipdst + "    " + self.sname + "    " + self.szone + "    " + self.qtype
      

      

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

        a = Packet(timestamp,ipdst,sname,szone,qtype)
        
#        line = dict('time': timestamp,
#                    'ipdst': ipdst,
#                    'sname': sname,
#                    'szone': szone,
#                    'qtype': qtype)


#        '{timestamp} {ipdst} {name} {zone} {type}'.format(
#            timestamp=datetime.datetime.utcnow().replace(microsecond=0),
#            ipdst=pkt.sprintf('%IP.dst%'),
#            name=name or '@',
#            zone=zone,
#            type=q.sprintf('%qtype%'),)

        if out_file:
            out_file.write('%s\n' % line)
            out_file.flush()
            print a.displayPacket()
        else:
            print a.displayPacket()
        # return pkt.sprintf("%IP.src%:%UDP.sport% >>> %IP.dst%:%UDP.dport% ") + dnsqr.sprintf("%qname% %qclass% %qtype%").replace("'","")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture DNS queries and output to specified directory')
    parser.add_argument('--output', '-o', help='write dumps to folder')

    args = parser.parse_args()
    print >> sys.stderr, 'Capturing DNS requests..'

    try:
        if args.output:
            out_file = open(args.output, 'a')
        else:
            out_file = None
        sniff(filter='port 53', prn=scanner, store=0)
    except KeyboardInterrupt:
        exit(0)
    finally:
        if out_file:
            out_file.close()
