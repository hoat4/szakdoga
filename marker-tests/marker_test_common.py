from scapy.all import *

min_port = 50001
max_port = 50015

def getFlowLengthByDstPort(dport):
    return {
        50001: 100, 
        50002: 500,
        50003: 1000, 
        50004: 5000,
        50005: 10000, 
        50006: 50000,
        50007: 100000, 
        50008: 500000,
        50009: 1000000, 
        50010: 5000000,
        50011: 10000000, 
        50012: 50000000,
        50013: 100000000, 
        50014: 500000000,
        50015: 1000000000
    }[dport]

def getFlowLength(packet):
    return getFlowLengthByDstPort(packet[UDP].dport)


class Flow:
    def __init__(self, dstport):
        self.srcport = random.randint(10000, 60000)
        self.dstport = dstport
        self.sent = 0
        self.length = getFlowLengthByDstPort(self.dstport)
        self.remainingBytes = self.length

    def sendPacketWithExpectedRank(self, expectedRank):
        print("Send packet with on " + str(self.srcport) + "-" + str(self.dstport) + ": remaining " + 
               str(self.remainingBytes) + "/" + str(self.length) + " bytes, " + 
               "expected rank: " + str(expectedRank))
        payload = str(expectedRank) + ("_" * 500)
        p = IP(dst="10.0.0.1") / UDP(sport = self.srcport, dport=self.dstport) / payload
        send(p, verbose=False)
        self.remainingBytes -= len(payload.encode())
