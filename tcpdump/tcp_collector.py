#read tcpdump output from stdin line by line

import sys

while True:
    for line in sys.stdin.readlines():
    print line
    
