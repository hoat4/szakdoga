from scapy.all import *
import time

for i in range(0, 10):
    p = IP(dst="10.0.0.1", id = 1) / UDP(sport = 12345, dport=50005) / ("Hello world!" + str(i))
    send(p)
    time.sleep(1)
