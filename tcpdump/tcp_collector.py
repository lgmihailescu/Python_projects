#read tcpdump output from stdin line by line

import sys

while true:
    for line in sys.stdin.readlines():
        print line,
    
