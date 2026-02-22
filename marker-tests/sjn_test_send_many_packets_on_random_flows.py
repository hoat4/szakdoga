from scapy.all import *
from marker_test_common import *
import math

for i in range(1, 1000):
    flow = Flow(random.randint(min_port, max_port))
    expectedRank = math.floor(math.sqrt(getFlowLengthByDstPort(flow.dstport)))
    flow.sendPacketWithExpectedRank(expectedRank)

