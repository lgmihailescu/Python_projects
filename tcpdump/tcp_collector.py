#read tcpdump output from stdin line by line

import sys

for line in sys.stdin.readlines():
    if line[0] == '#':
        print line
