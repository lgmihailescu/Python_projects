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
import operator
import itertools
from collections import defaultdict
from scapy.all import *

queue = Queue.Queue()
           
log_files = {}
whois_logs = {}


zone_queue = Queue.Queue()
IP_queue = Queue.Queue()

#list_by_zones = []
#list_by_IP = []





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
            #queue.join()
            time.sleep(5)

class Thread_aggregate_zone(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
          
    def run(self):
        list_zones = []
        zlist = defaultdict(list)
        while True:
            try:
                if not queue.empty():
                    #grabs list from queue
                    list_zones.append(self.queue.get())
            except:
                print "error"
            
            # execution
            try:
                for a, b in list_zones:
                    zlist[a].append(b)
            except:
                zlist = []
            print zlist.items()               
            #signals to queue job is done
            #queue.join()
                self.queue.task_done()
            time.sleep(10)





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

        
        #list_by_zones.append([a.szone,dict(timestamp=a.time, ip=a.ipsrc, query=a.qtype)])
        #list_by_IP.append([a.ipsrc,dict(timestamp=a.time, ip=a.ipsrc)])


        zone_queue.put([a.szone,dict(timestamp=a.time, ip=a.ipsrc, query=a.qtype)])
        IP_queue.put([a.ipsrc,dict(timestamp=a.time, ip=a.ipsrc)])

        
        log(a)
        whois_log(a)



def whois_query(ip):
    try:
        result = whois.query(ip)
        return result.name
    except:
        return "ERROR"


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
    
    m = Thread_aggregate_zone(zone_queue)
    m.setDaemon(True)
    m.start()

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
        #print list_by_zones
        #print list_by_IP

   
    
        
            
    queue.join()
    zone_queue.join()        
