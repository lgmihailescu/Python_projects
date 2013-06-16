#!/usr/bin/env python

import os
import datetime
import argparse
import whois
import sys
import Queue
import threading
import time
import socket

queue = Queue.Queue()
           
log_files = {}
whois_logs = {}

#response = ""


from scapy.all import *

class Packet:
    def __init__(self, time, ipsrc, port, sname, szone, qtype):
        self.time = str(time)
        self.ipsrc = str(ipsrc)
        self.sname = str(sname)
        self.szone = str(szone)
        self.qtype = str(qtype)
        self.port = str(port)
        
    def display_packet(self):
        return self.time + "    " + self.ipsrc + "    " + self.port + "    " + self.sname + "    " + self.szone + "    " + self.qtype

class Thread_Whois(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
          
    def run(self):
        while True:
            
            #grabs IP from queue
            target = self.queue.get()
            
            #WHOIS execution
            try:
                x = socket.gethostbyaddr(target)
            except socket.herror:
                x = 'No results returned'
                
            response = whois_query(x[0])
            
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
        ipsrc=pkt.sprintf('%IP.src%')
        port=pkt.sprintf('%UDP.dport%')

        a = Packet(timestamp,ipsrc,port,sname,szone,qtype)
        
        log(a)
        whois_log(a)



def whois_query(ip):
    result = whois.query(ip)
    return result.name


def whois_log(packet):
    if packet.ipsrc not in whois_logs:
        whois_logs[packet.ipsrc] = open(os.path.join(curr_dir, args.output, "WHOIS", packet.ipsrc + '.log'), 'a')
        queue.put(packet.ipsrc)
        

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
        sniff(filter='udp src port 53', prn=scanner, store=0)
    except KeyboardInterrupt:
        exit(0)
    finally:
        for logfile in log_files:
            log_files[logfile].close()
            print "Closed %s" % log_files[logfile].name
        for whois_log in whois_logs:
            whois_logs[whois_log].close()
            print "Closed %s" % whois_logs[whois_log].name
            
    queue.join()
        
