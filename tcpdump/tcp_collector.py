#read tcpdump output from stdin line by line

import sys


for line in sys.stdin.readlines():
    print line,
    
