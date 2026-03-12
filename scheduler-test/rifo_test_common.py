from scapy.all import *

def sendWithRank(rank, len):
    print("Send with rank " + str(rank))
    p = IP(dst="10.0.0.1", id = rank) / UDP(sport = 12345, dport=50005) / ("a" * len) 
    send(p)
