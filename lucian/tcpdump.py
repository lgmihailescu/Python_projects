#!/usr/bin/env python

import os
import datetime
import argparse
import whois
import sys
import Queue
import threading
import time

queue = Queue.Queue()
           
log_files = {}
whois_logs = {}

#response = ""


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

class Thread_Whois(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
          
    def run(self,packet):
        while True:
            
            #grabs IP from queue
            target = self.queue.get()
            
            #WHOIS execution
            response = whois_query(target)
            out = open(os.path.join(curr_dir, args.output, "WHOIS", target + '.log'), 'a')
            out.write('%s\n' % response)
            out.flush()
            os.fsync(out.fileno())
            
            
            #signals to queue job is done
            self.queue.task_done()
            time.sleep(5)


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
        whois_log(a)



def whois_query(ip):
    result = whois.query(ip)
    return result.name


def whois_log(packet):
    if packet.ipdst not in whois_logs:
        whois_logs[packet.ipdst] = open(os.path.join(curr_dir, args.output, "WHOIS", packet.ipdst + '.log'), 'a')
        queue.put(packet.ipdst)
        

def log(packet):
    if packet.szone not in log_files:
        log_files[packet.szone] = open(os.path.join(curr_dir, args.output, packet.szone + '.log'), 'a')
    log_files[packet.szone].write('%s\n' % packet.display_packet())
    log_files[packet.szone].flush()
    os.fsync(log_files[packet.szone].fileno())
    print packet.display_packet()
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Capture DNS queries and output to specified directory')
    parser.add_argument('--output', '-o', help='write dumps to specified folder')

    args = parser.parse_args()
    print >> sys.stderr, 'Capturing DNS requests..'

    if args.output:
        os.mkdir(args.output)
        
        if not os.path.exists(os.path.join(args.output,"WHOIS")):
                              os.mkdir(os.path.join(args.output,"WHOIS"))
            
        curr_dir = os.getcwd()
    else:
        out_file = None


    t = Thread_Whois(queue)
    t.setDaemon(True)
    t.start()


    try:
        sniff(filter='dst port 53', prn=scanner, store=0)
    except KeyboardInterrupt:
        exit(0)
    finally:
        for logfile in log_files:
            log_files[logfile].close()
            print "Closed %s" % log_files[logfile].name
        for whois_log in whois_logs:
            whois_logs[whois_log].close()
            print "Closed %s" % whois_logs[whois_log].name
            
            
        
