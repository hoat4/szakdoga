from scapy.all import *
import math
from marker_test_common import *

p = IP(dst="10.0.0.1") / UDP(sport = 12345, dport=50005) / str(math.floor(math.sqrt(getFlowLengthByDstPort(50005))))
send(p)


