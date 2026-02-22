from scapy.all import *
import marker_test_common
import math

receivedBytesByFlow = {}

def megjott(x):
    flowID = str(x[UDP].sport)+"-"+str(x[UDP].dport)
    if flowID not in receivedBytesByFlow:
        receivedBytesByFlow[flowID] = 0
    remaining = marker_test_common.getFlowLength(x) - receivedBytesByFlow[flowID]
    receivedBytesByFlow[flowID] += len(bytes(x[UDP].payload))
    expectedRank = int(bytes(x[UDP].payload).decode().replace("_", ""))
    print("Expected rank: " + str(expectedRank) + ", "
          "actual rank:" + str(x[IP].id) + 
          (" OK" if x[IP].id == expectedRank else " WRONG") +
          ", payload length:" + str(len(bytes(x[UDP].payload))) + 
          ", flow length: " + str(marker_test_common.getFlowLength(x)) +
          ", received bytes in this flow: " + str(receivedBytesByFlow[flowID]) + 
          ", remaining bytes in this flow: " + str(remaining)
    )
    sys.stdout.flush()

sniff(iface = 'h1-eth0', filter = "udp dst portrange 50001-50015", prn=megjott)
