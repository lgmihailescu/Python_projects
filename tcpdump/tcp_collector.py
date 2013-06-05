#read tcpdump output from stdin line by line

import sys

while 1:
    try:
        line = sys.stdin.readline()
    except KeyboardInterrupt:
        break

    if not line:
        break

    print line
